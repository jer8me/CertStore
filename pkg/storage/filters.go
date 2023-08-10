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
	PublicKeyType     string
	IsCA              bool
	NotCA             bool
	HasPrivateKey     bool
	NoPrivateKey      bool
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

func (qb *QueryBuilder) AddArg(arg any) {
	qb.Args = append(qb.Args, arg)
}

func (qb *QueryBuilder) Filter(query string) {
	if qb.HasFilter {
		// Filters are additive: use intersection to add another filter
		qb.WriteString(" INTERSECT ")
	} else {
		qb.HasFilter = true
	}
	qb.WriteString(query)
}

func (qb *QueryBuilder) FilterLike(query, value string) {
	if value == "" {
		// No value to filter on
		return
	}
	qb.Filter(query)
	qb.WriteString(" LIKE ?")
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
	qb.AddArg(arg.String())
}

func (qb *QueryBuilder) FilterEqual(query string, value any) {
	if value == "" {
		// No value to filter on
		return
	}
	qb.Filter(query)
	qb.WriteString(" = ?")
	qb.AddArg(value)
}

func (qb *QueryBuilder) String() string {
	return qb.Builder.String()
}
