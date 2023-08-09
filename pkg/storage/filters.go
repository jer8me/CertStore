package storage

import (
	"regexp"
	"strings"
)

type SearchFilter struct {
	San               string
	Serial            string
	Issuer            string
	IssuerCn          string
	IssuerCountry     string
	IssuerLocality    string
	IssuerState       string
	IssuerStreet      string
	IssuerOrg         string
	IssuerOrgUnit     string
	IssuerPostalCode  string
	Subject           string
	SubjectCn         string
	SubjectCountry    string
	SubjectLocality   string
	SubjectState      string
	SubjectStreet     string
	SubjectOrg        string
	SubjectOrgUnit    string
	SubjectPostalCode string
}

type QueryBuilder struct {
	strings.Builder
	HasFilter bool
	Args      []any
}

var likeSpecialRe = regexp.MustCompile(`[%_\\]`)

func NewQueryBuilder() *QueryBuilder {
	return &QueryBuilder{}
}

func (qb *QueryBuilder) WriteString(s string) {
	qb.Builder.WriteString(s)
}

func (qb *QueryBuilder) FilterLike(query, value string) {
	if value == "" {
		// No value to filter on
		return
	}
	if qb.HasFilter {
		// Filters are additive: use intersection to add another filter
		qb.Builder.WriteString(" INTERSECT ")
	} else {
		qb.HasFilter = true
	}
	qb.Builder.WriteString(query)
	qb.Builder.WriteString(" LIKE ?")
	// Build argument string
	var arg strings.Builder
	arg.WriteByte('%')
	if strings.ContainsAny(value, `%_\`) {
		// Need to escape special characters
		qb.Builder.WriteString(` ESCAPE '\'`)
		// Replace special characters with their escaped version (\ prefix)
		arg.WriteString(likeSpecialRe.ReplaceAllString(value, `\$0`))
	} else {
		arg.WriteString(value)
	}
	arg.WriteByte('%')
	qb.Args = append(qb.Args, arg.String())
}

func (qb *QueryBuilder) String() string {
	return qb.Builder.String()
}
