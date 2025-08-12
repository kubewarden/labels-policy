#!/usr/bin/env bats

@test "accept labels are not on denylist" {
	run kwctl run annotated-policy.wasm \
		-r test_data/ingress.json \
		--settings-json '{"criteria": "doesNotContainAnyOf" ,"values": ["foo", "bar"]}'
	# this prints the output when one the checks below fails
	echo "output = ${output}"

	# request accepted
	[ "$status" -eq 0 ]
	[ $(expr "$output" : '.*allowed.*true') -ne 0 ]
}

@test "reject because labels is on denylist" {
	run kwctl run annotated-policy.wasm \
		-r test_data/ingress.json \
		--settings-json '{"criteria": "doesNotContainAnyOf" ,"values": ["cc-center", "bar"]}'

	# this prints the output when one the checks below fails
	echo "output = ${output}"

	# request rejected
	[ "$status" -eq 0 ]
	[ $(expr "$output" : '.*allowed.*false') -ne 0 ]
	[ $(expr "$output" : '.*The following invalid labels were found: cc-center.*') -ne 0 ]
}

@test "reject because a required label does not exist" {
	run kwctl run policy.wasm \
		-r test_data/ingress.json \
		--settings-json '{"criteria": "doesNotContainOtherThan" ,"values": ["foo", "bar"]}'

	# this prints the output when one the checks below fails
	echo "output = ${output}"

	# request rejected
	[ "$status" -eq 0 ]
	[ $(expr "$output" : '.*allowed.*false') -ne 0 ]
	[ $(expr "$output" : '.*The following labels were found that should not be present: .*') -ne 0 ]
}
