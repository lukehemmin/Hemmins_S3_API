package s3

import "encoding/xml"

// ListAllMyBucketsResult is the S3 XML response body for GET Service (ListBuckets).
// Per AWS S3 API reference and s3-compatibility-matrix.md section 3.
// The XML namespace is required by the S3 protocol; SDKs check for it.
type ListAllMyBucketsResult struct {
	XMLName xml.Name     `xml:"http://s3.amazonaws.com/doc/2006-03-01/ ListAllMyBucketsResult"`
	Owner   s3Owner      `xml:"Owner"`
	Buckets s3BucketList `xml:"Buckets"`
}

type s3Owner struct {
	ID          string `xml:"ID"`
	DisplayName string `xml:"DisplayName"`
}

type s3BucketList struct {
	Bucket []s3Bucket `xml:"Bucket"`
}

type s3Bucket struct {
	Name         string `xml:"Name"`
	CreationDate string `xml:"CreationDate"`
}

// s3TimeFormat is the ISO 8601 timestamp format expected by S3 SDKs.
// Matches the AWS S3 response format: YYYY-MM-DDTHH:MM:SS.sssZ
const s3TimeFormat = "2006-01-02T15:04:05.000Z"

// ListBucketV2Result is the S3 XML response body for ListObjectsV2 (GET /{bucket}?list-type=2).
// Per AWS S3 API reference and s3-compatibility-matrix.md section 2.4.
// The XML namespace is required by SDKs.
type ListBucketV2Result struct {
	XMLName               xml.Name       `xml:"http://s3.amazonaws.com/doc/2006-03-01/ ListBucketResult"`
	Name                  string         `xml:"Name"`
	Prefix                string         `xml:"Prefix"`
	Delimiter             string         `xml:"Delimiter,omitempty"`
	MaxKeys               int            `xml:"MaxKeys"`
	KeyCount              int            `xml:"KeyCount"`
	IsTruncated           bool           `xml:"IsTruncated"`
	ContinuationToken     string         `xml:"ContinuationToken,omitempty"`
	NextContinuationToken string         `xml:"NextContinuationToken,omitempty"`
	Contents              []s3ObjectItem `xml:"Contents"`
	CommonPrefixes        []s3CPEntry    `xml:"CommonPrefixes"`
}

// s3ObjectItem represents a single <Contents> entry in a ListObjectsV2 response.
type s3ObjectItem struct {
	Key          string `xml:"Key"`
	LastModified string `xml:"LastModified"`
	ETag         string `xml:"ETag"`
	Size         int64  `xml:"Size"`
	StorageClass string `xml:"StorageClass"`
}

// s3CPEntry represents a single <CommonPrefixes> entry in a ListObjectsV2 response.
type s3CPEntry struct {
	Prefix string `xml:"Prefix"`
}
