{{- if eq (len .AuthorizationCrt.URIs) 1 }}
{{-   $san := printf "%s" (index .AuthorizationCrt.URIs 0) }}
{{-   $prefix := "spiffe://@TRUST_DOMAIN@/@HOST_PREFIX@/" }}
{{-   if eq .Type "user" }}
{{-     $prefix = "spiffe://@TRUST_DOMAIN@/@USER_PREFIX@/" }}
{{-   end }}
{{-   if hasPrefix $prefix $san }}
{{-     $name := trimPrefix $prefix $san }}
{
  "type": {{ toJson .Type }},
  "keyId": {{ toJson $san }},
  "principals": {{ splitList "/" $name | toJson }},
  "extensions": {{ toJson .Extensions }},
  "criticalOptions": {{ toJson .CriticalOptions }}
}
{{-   else }}
{{-     fail (printf "Identity %s is not authorized for SSH %s certificates" $san .Type) }}
{{-   end }}
{{- else }}
{{-   fail "Authorization certificate must contain exactly one URI SAN" }}
{{- end }}
