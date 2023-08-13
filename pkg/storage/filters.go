package storage

import (
	"regexp"
	"strings"
	"time"
)

type SearchFilter struct {
	ExpireBefore        time.Time
	San                 string
	Serial              string
	Issuer              string
	IssuerCn            string
	IssuerCountry       string
	IssuerLocality      string
	IssuerState         string
	IssuerStreet        string
	IssuerOrg           string
	IssuerOrgUnit       string
	IssuerPostalCode    string
	Subject             string
	SubjectCn           string
	SubjectCountry      string
	SubjectLocality     string
	SubjectState        string
	SubjectStreet       string
	SubjectOrg          string
	SubjectOrgUnit      string
	SubjectPostalCode   string
	PublicKeyAlgorithms []string
	IsCA                bool
	NotCA               bool
	HasPrivateKey       bool
	NoPrivateKey        bool
}

type QueryBuilder struct {
	strings.Builder
	HasFilter bool
	Args      []any
}

var likeSpecialRe = regexp.MustCompile(`[%_\\]`)

// NewQueryBuilder create a new QueryBuilder object.
func NewQueryBuilder() *QueryBuilder {
	return &QueryBuilder{}
}

// addArg adds a single argument value to the arg slice.
func (qb *QueryBuilder) addArg(arg any) {
	qb.Args = append(qb.Args, arg)
}

// addArgs adds a slice of argument values to the arg slice.
func (qb *QueryBuilder) addArgs(args []any) {
	qb.Args = append(qb.Args, args...)
}

// Filter adds an additive filter (AND) to the list of filters.
// Additional strings can be passed to build a filter from multiple parts.
// Filter does not modify the slice of arguments.
// The caller must ensure that whitespaces are appropriately provided.
func (qb *QueryBuilder) Filter(query string, more ...string) {
	if qb.HasFilter {
		// Filters are additive: use intersection to add another filter
		qb.WriteString(" INTERSECT ")
	} else {
		qb.HasFilter = true
	}
	qb.WriteString(query)
	for _, s := range more {
		qb.WriteString(s)
	}
}

// FilterLike builds a LIKE filter for text matching.
// This filter will match any text that includes the string provided, regardless of the case.
func (qb *QueryBuilder) FilterLike(query, value string) {
	if value == "" {
		// No value to filter on
		return
	}
	qb.Filter(query, " LIKE ?")
	// Build argument string
	var arg strings.Builder
	arg.WriteByte('%')
	if strings.ContainsAny(value, `%_\`) {
		// Need to escape special characters
		qb.WriteString(` ESCAPE '\'`)
		// Replace special characters with their escaped version (\ prefix)
		arg.WriteString(likeSpecialRe.ReplaceAllString(value, `\$0`))
	} else {
		arg.WriteString(value)
	}
	arg.WriteByte('%')
	qb.addArg(arg.String())
}

// FilterCompare builds a comparison filter with the operator provided.
func (qb *QueryBuilder) FilterCompare(query, operator string, value any) {
	qb.Filter(query, " ", operator, " ?")
	qb.addArg(value)
}

// FilterIn builds a filter that matches any value in the slice of values provided.
// The match must be an exact match (no collation).
func (qb *QueryBuilder) FilterIn(query string, values []any) {
	if len(values) == 0 {
		// No values to filter on
		return
	}
	placeholders := strings.Repeat("?,", len(values))
	placeholders = strings.TrimSuffix(placeholders, ",")
	qb.Filter(query, " IN (", placeholders, ")")
	qb.addArgs(values)
}

// String returns the filter string.
func (qb *QueryBuilder) String() string {
	return qb.Builder.String()
}
