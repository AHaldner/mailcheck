package checks

import (
	"fmt"
	"strings"
)

type selectorFamily struct {
	prefix string
	start  int
	end    int
	width  int
}

const curatedDKIMSelectors = `
s1
google
mandrill
default
smtpapi
200608
mail
20230601
k1
m1
krs
mailo
pic
selector1
intercom
smtp
mx
mailjet
hs1
hs2
s2
dk
dkim
kl
k2
selector2
10dkim1
cm
spop1024
key1
zendesk1
neolane
s1024
11dkim1
mta
50dkim1
email
key2
sailthru
sm
12dkim1
ep1
gears
dkim1024
0
acdkim1
qualtrics
api
mindbox
ml
pm
zendesk2
fnc
resend
s2048
scph0420
nc2048
spop
v1
dk1024-2012
dk2016
ed-dkim-v3
ngpweb3
sim
us
ap3
bdk
ei
emv
fm2
fnt
kl2
litesrv
mixpanel
pepipost
scph0521
scph0816
sg
sign
strong1
20161025
20221208
cka
cs2013
dmddkim
ed-dkim
fde
firebase2
fm1
mg
pp-dkim1
proddkim1024
protonmail
scph0321
scph0616
scph0720
sv
x
20210112
51dkim1
class
dyn
ecm1
firebase1
m2
mail2
mailing
mte1
nc
pg
pp-epsilon1
protonmail3
s1024a
scph0122
scph0221
scph0318
scph0421
scph0423
scph0522
scph0618
scph0722
scph0819
scph0820
scph0920
scph0923
scph1020
scph1221
scph1222
smtpout
spop2048
squarespace
1522905413783
15below
crisp
d2048-1
d4815
dkimrnt
fm3
mail1
mailmodo
medalliadefault
memdkim
pps1
prod
s1024-1.bh
salesmanago
scph0120
scph0322
scph0419
scph0518
`

var selectorFamilies = []selectorFamily{
	{prefix: "selector", start: 1, end: 3},
	{prefix: "key", start: 1, end: 4},
	{prefix: "k", start: 1, end: 4},
	{prefix: "s", start: 1, end: 4},
	{prefix: "m", start: 1, end: 3},
	{prefix: "fm", start: 1, end: 3},
	{prefix: "hs", start: 1, end: 2},
	{prefix: "zendesk", start: 1, end: 2},
	{prefix: "firebase", start: 1, end: 2},
	{prefix: "protonmail", start: 1, end: 3},
	{prefix: "mail", start: 1, end: 4},
}

var providerSelectors = []string{
	"resend",
	"sendgrid",
	"mailgun",
	"mailchimp",
	"mandrill",
	"postmark",
	"sparkpost",
	"mailjet",
	"brevo",
	"sendinblue",
	"hubspot",
	"klaviyo",
	"customerio",
	"salesforce",
	"pardot",
	"amazonses",
	"ses",
	"convertkit",
	"campaignmonitor",
	"activecampaign",
}

var fastDKIMSelectors = []string{
	"google",
	"default",
	"selector1",
	"selector2",
	"mail",
	"dkim",
	"s1",
	"s2",
	"k1",
	"k2",
	"k3",
	"m1",
	"mx",
	"smtp",
	"cm",
	"mandrill",
	"sendgrid",
	"mailgun",
	"mailchimp",
	"postmark",
	"sparkpost",
	"mailjet",
	"brevo",
	"sendinblue",
	"hubspot",
	"klaviyo",
	"amazonses",
	"ses",
	"resend",
	"protonmail",
	"zendesk1",
	"zendesk2",
}

func dkimSelectorCandidates(explicit []string, deep bool) []string {
	seen := make(map[string]struct{})
	candidates := make([]string, 0, 192)

	add := func(selector string) {
		selector = normalizeSelector(selector)
		if selector == "" {
			return
		}
		if _, ok := seen[selector]; ok {
			return
		}

		seen[selector] = struct{}{}
		candidates = append(candidates, selector)
	}

	if deep {
		for selector := range strings.FieldsSeq(curatedDKIMSelectors) {
			add(selector)
		}

		for _, family := range selectorFamilies {
			for value := family.start; value <= family.end; value++ {
				if family.width > 0 {
					add(fmt.Sprintf("%s%0*d", family.prefix, family.width, value))
					continue
				}

				add(fmt.Sprintf("%s%d", family.prefix, value))
			}
		}

		for _, selector := range providerSelectors {
			add(selector)
		}

		for _, selector := range explicit {
			add(selector)
		}

		return candidates
	}

	for _, selector := range fastDKIMSelectors {
		add(selector)
	}

	for _, selector := range explicit {
		add(selector)
	}

	return candidates
}

func normalizeSelector(selector string) string {
	return strings.ToLower(strings.TrimSpace(selector))
}
