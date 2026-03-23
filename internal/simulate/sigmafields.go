package simulate

// ValidSigmaFields is the set of known Sigma field names for observable validation.
// Source of truth: github.com/craftedsignal/backend/pkg/domain/sigmafields/registry.go
// Keep in sync when adding new fields to field_resolver.go platform maps.
var ValidSigmaFields = map[string]bool{
	"Image": true, "OriginalFileName": true, "CommandLine": true,
	"ParentImage": true, "ParentCommandLine": true, "User": true,
	"IntegrityLevel": true, "CurrentDirectory": true, "ProcessId": true,
	"ParentProcessId": true, "Company": true, "Product": true,
	"Description": true, "LogonId": true, "imphash": true,
	"TargetFilename": true, "TargetObject": true, "CreationUtcTime": true,
	"PreviousCreationUtcTime": true,
	"SourceIP": true, "DestinationIP": true, "SourcePort": true,
	"DestinationPort": true, "DestinationHostname": true, "Protocol": true,
	"Initiated": true,
	"Details": true, "ObjectValueName": true,
	"EventID": true, "EventCode": true, "EventType": true, "Channel": true,
	"Provider_Name": true, "LogonType": true,
	"QueryName": true, "QueryType": true, "QueryResults": true,
	"Hashes": true, "md5": true, "sha1": true, "sha256": true,
	"ServiceName": true, "ServiceFileName": true, "ImageLoaded": true,
	"SignatureStatus": true, "Signature": true, "Signed": true,
	"SourceImage": true, "TargetImage": true, "GrantedAccess": true,
	"CallTrace": true,
	"TargetUserName": true, "SubjectUserName": true,
	"SubjectDomainName": true, "TargetDomainName": true,
	"SourceNetworkAddress": true, "WorkstationName": true,
	"IpAddress": true, "IpPort": true,
	"PipeName": true,
	"RuleName": true, "UtcTime": true, "Device": true,
	"AccessMask": true, "ObjectType": true, "ObjectName": true,
	"ShareName": true, "RelativeTargetName": true, "SubjectUserSid": true,
}
