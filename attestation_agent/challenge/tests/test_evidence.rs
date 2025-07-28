use serde_json::json;
use challenge::evidence::GetEvidenceRequest;

#[test]
fn test_deserialize_get_evidence_request_without_attesters() {
    let json = json!({
        "nonce_type": "verifier",
        "nonce": {
            "iat": 1749721474,
            "value": "ImQiIm+6vwdKhAH6FC58XFxfuQ8TWvGxO6qlYwQK6P11Fi/ole/VMN9+4PJodOGt8E6+sbkfJOmuU96/Wc0JSw==",
            "signature": "eEZHR66P+wPOuTTJanS0OhjqPLquLlJci2KxdptPz8+yLJpOVsOSUDsdeadv0a3aFStY130NdthZ/aBWQNWusblABhq0uepaS/29UFVUXT9tbSQG2PGhsG1+NQxkNr1/u/zktQLqThk9oxiEF8nwFozZTyaSJAvzV5b/3lIvJxa588OUug6PhurMKxIOx0KqpPxv/sHq74IUjW50r4ZtLUlRUxERLPORuobHaCjmJ9UMby6NZ6xlvjKVb5gAWGcupZS4M1PSAYb3+90MpflFrfu6gGLbe29o5CIWDgrwMYfgFGsJ9GaWdTZ20rbdn60USYPvManw0dkNr4Q4tKhs4VYX+IkByVddfexg9t5en/wC8axVk2zH6C7edoepgZfW2AJo8TKYdb8XEGIBteadlvGohX3w957/uZc3lAcJmNEImYTEzwJu4aj4pcOH54YhOWoIYY3fGaIw5JQ87VslG256VUo0h8QIlYUEtEisFpZzwuInOlNwB9o4TMbPuosd"
        },
        "attester_data": {"test_key": "test_value"}
    });

    let result: Result<GetEvidenceRequest, _> = serde_json::from_value(json);
    assert!(result.is_err());
}
