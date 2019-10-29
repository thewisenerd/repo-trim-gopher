package main

import (
	"crypto/md5"
	"crypto/sha1"
	"encoding/json"
	"encoding/xml"
	"flag"
	"fmt"
	"github.com/hashicorp/go-version"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync/atomic"
	"time"
)

type MetaDataRoot struct {
	XMLName    xml.Name           `xml:"metadata"`
	GroupId    string             `xml:"groupId"`
	ArtifactId string             `xml:"artifactId"`
	Versioning MetaDataVersioning `xml:"versioning"`
}

type MetaDataVersioning struct {
	XMLName     xml.Name `xml:"versioning"`
	Release     string   `xml:"release"`
	Versions    []string `xml:"versions>version"`
	LastUpdated string   `xml:"lastUpdated"`
}

type CacheKey struct {
	GroupId    string
	ArtifactId string
}

type CacheResponse struct {
	metadata   MetaDataRoot
	marshalled string
	md5        string
	sha1       string
}

type TrimEntry struct {
	Key   int    `json:"key"`
	Count uint64 `json:"count"`
}

type CacheEntry struct {
	original  CacheResponse
	processed CacheResponse
	trimmed   []TrimEntry
	ts        int64 // epoch seconds
}

type StatsEntry struct {
	GroupId    string      `json:"groupId"`
	ArtifactId string      `json:"artifactId"`
	Trimmed    []TrimEntry `json:"trimmed"`
	Ts         int64       `json:"ts"`
}

type Stats struct {
	TotalHits  uint64        `json:"totalHits"`
	OriginHits uint64        `json:"originHits"`
	CacheHits  uint64        `json:"cacheHits"`
	TrimCount  uint64        `json:"trimCount"`
	Entries    *[]StatsEntry `json:"entries"`
}

// https://stackoverflow.com/a/48801414
func trimLeftChar(s string) string {
	for i := range s {
		if i > 0 {
			return s[i:]
		}
	}
	return s[:0]
}

func readRemotePath(path string) (response *[]byte, err error) {
	start := time.Now()
	resp, err := http.Get(path)
	fmt.Printf("[%s]:[%v]\n", path, time.Since(start))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Check server response
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bad status: %s", resp.Status)
	}

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading body of path [%s]: %s", path, err.Error())
	}

	return &respBody, nil
}

func fetchMetaData(remote string, groupId string, artifactId string) (metaResponse *CacheResponse, retErr error) {
	var metaDataPath = remote + "/" + strings.ReplaceAll(groupId, ".", "/") + "/" + artifactId + "/maven-metadata.xml"
	metaDataRaw, metaDataRawError := readRemotePath(metaDataPath)
	if metaDataRawError != nil {
		return nil, metaDataRawError
	}

	var metaData MetaDataRoot
	metaDataUnmarshalError := xml.Unmarshal(*metaDataRaw, &metaData)
	if metaDataUnmarshalError != nil {
		return nil, metaDataUnmarshalError
	}

	xmlData, metaDataMarshalError := xml.MarshalIndent(metaData, "", "  ")
	if metaDataMarshalError != nil {
		return nil, metaDataMarshalError
	}

	finalXMLData := xml.Header + string(xmlData) + "\n"
	finalXMLDataMD5 := fmt.Sprintf("%x", md5.Sum([]byte(finalXMLData)))
	finalXMLDataSHA1 := fmt.Sprintf("%x", sha1.Sum([]byte(finalXMLData)))

	var meta = CacheResponse{metadata: metaData, marshalled: finalXMLData, md5: finalXMLDataMD5, sha1: finalXMLDataSHA1}
	return &meta, nil
}

func makeVersionFromString(s string) (r *version.Version, err error) {
	var re = regexp.MustCompile(`([0-9.]+)-[0-9a-z]+`)
	if re.MatchString(s) {
		ret, e := version.NewVersion(re.FindStringSubmatch(s)[1])
		return ret, e
	} else {
		ret, e := version.NewVersion(s)
		return ret, e
	}
}

func (v CacheResponse) ProcessResponse(versionCount int) (r *CacheEntry, err error) {
	var versionListMap = make(map[int][]string)

	metadata := &v.metadata
	versions := metadata.Versioning.Versions
	newVersions := make([]string, 0)

	for _, versionStr := range versions {
		v, versionErr := makeVersionFromString(versionStr)
		if versionErr != nil {
			return nil, versionErr
		}
		segments := v.Segments()
		if len(segments) == 0 {
			return nil, fmt.Errorf("len(segments) in version %s is zero", versionStr)
		}
		key := segments[0]
		versionListMap[key] = append(versionListMap[key], versionStr)
	}

	// To store the keys in slice in sorted order
	var keys []int
	for k := range versionListMap {
		keys = append(keys, k)
	}
	sort.Ints(keys)

	var trimEntries []TrimEntry

	for _, k := range keys {
		versionList := versionListMap[k]
		if versionCount > 0 && len(versionList) > versionCount {
			sort.Slice(versionList, func(i, j int) bool {
				left, _ := makeVersionFromString(versionList[i])
				right, _ := makeVersionFromString(versionList[j])

				return left.LessThan(right)
			})
			for _, e := range versionList[len(versionList)-versionCount:] {
				newVersions = append(newVersions, e)
			}
			trimCount := uint64(len(versions) - len(newVersions))
			trimEntries = append(trimEntries, TrimEntry{k, trimCount})
		} else {
			for _, e := range versionList {
				newVersions = append(newVersions, e)
			}
		}
	}

	newVersioning := metadata.Versioning
	newMetaData := v.metadata

	newVersioning.Versions = newVersions
	newMetaData.Versioning = newVersioning

	xmlData, metaDataMarshalError := xml.MarshalIndent(newMetaData, "", "  ")
	if metaDataMarshalError != nil {
		return nil, metaDataMarshalError
	}

	finalXMLData := xml.Header + string(xmlData) + "\n"
	finalXMLDataMD5 := fmt.Sprintf("%x", md5.Sum([]byte(finalXMLData)))
	finalXMLDataSHA1 := fmt.Sprintf("%x", sha1.Sum([]byte(finalXMLData)))

	var response = CacheResponse{metadata: newMetaData, marshalled: finalXMLData, md5: finalXMLDataMD5, sha1: finalXMLDataSHA1}
	return &CacheEntry{v, response, trimEntries, time.Now().Unix()}, nil
}

func writeOutput(groups []string, cacheEntry CacheEntry, w http.ResponseWriter) {
	if groups[3] == ".md5" {
		_, _ = w.Write([]byte(cacheEntry.processed.md5))
	} else if groups[3] == ".sha1" {
		_, _ = w.Write([]byte(cacheEntry.processed.sha1))
	} else if groups[3] == "" {
		_, _ = w.Write([]byte(cacheEntry.processed.marshalled))
	} else {
		http.Error(w, fmt.Sprintf("cannot understand extension %s", groups[3]), http.StatusInternalServerError)
	}
}

func proxyMetadata(w *http.ResponseWriter, baseUrl string, versionCount int, groups []string, cache *map[CacheKey]CacheEntry, stats *Stats) {
	var groupId = strings.ReplaceAll(trimLeftChar(groups[1]), "/", ".")
	var artifactId = groups[2]

	var cacheKey = CacheKey{GroupId: groupId, ArtifactId: artifactId}

	var cacheEntry, cacheEntryOk = (*cache)[cacheKey]
	if !cacheEntryOk {
		var computeResponse, computeResponseErr = fetchMetaData(baseUrl, groupId, artifactId)
		if computeResponseErr != nil {
			http.Error(*w, computeResponseErr.Error(), http.StatusInternalServerError)
		} else {
			processed, processErr := computeResponse.ProcessResponse(versionCount)
			if processErr != nil {
				http.Error(*w, processErr.Error(), http.StatusInternalServerError)
			} else {
				(*cache)[cacheKey] = *processed
				writeOutput(groups, *processed, *w)
			}
		}
		atomic.AddUint64(&stats.OriginHits, 1)
	} else {
		writeOutput(groups, cacheEntry, *w)
		atomic.AddUint64(&stats.CacheHits, 1)
	}
	atomic.AddUint64(&stats.TotalHits, 1)
}

func renderStats(w *http.ResponseWriter, cache *map[CacheKey]CacheEntry, stats *Stats) {
	newStats := stats
	entries := make([]StatsEntry, 0)
	totalTrimCount := uint64(0)
	for k, v := range *cache {
		entries = append(entries, StatsEntry{k.GroupId, k.ArtifactId, v.trimmed, v.ts})
		for _, e := range v.trimmed {
			totalTrimCount += e.Count
		}
	}
	newStats.Entries = &entries
	newStats.TrimCount = totalTrimCount
	jsonData, marshalError := json.MarshalIndent(newStats, "", "  ")
	if marshalError != nil {
		http.Error(*w, marshalError.Error(), http.StatusInternalServerError)
	} else {
		_, _ = (*w).Write(jsonData)
	}
}

func main() {
	var metadataRe = regexp.MustCompile(`([A-Za-z0-9-/]*)/([A-Za-z0-9-]*)/maven-metadata\.xml(\.md5|\.sha1)?`)
	var cache = make(map[CacheKey]CacheEntry)
	var stats = Stats{0, 0, 0, 0, nil}

	var baseUrl string
	var versionCount int

	flag.StringVar(&baseUrl, "b", "", "maven base URL [required]")
	flag.IntVar(&versionCount, "n", 0, "number of versions to keep, <= 0 for keep all")
	flag.Parse()
	if baseUrl == "" {
		flag.Usage()
		os.Exit(1)
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if metadataRe.MatchString(r.URL.Path) {
			var groups = metadataRe.FindStringSubmatch(r.URL.Path)
			proxyMetadata(&w, baseUrl, versionCount, groups, &cache, &stats)
		} else if r.URL.Path == "/stats" {
			renderStats(&w, &cache, &stats)
		} else {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		}
	})

	var err = http.ListenAndServe(":8043", nil)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "error starting server: %s\n", err.Error())
	}
}
