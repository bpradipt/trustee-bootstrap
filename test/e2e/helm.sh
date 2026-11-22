# Sourced by trustee-cvm.sh when E2E_DEPLOY=helm: the Trustee CVM comes
# from upstream's Trustee Helm chart and deploy/helm, not deploy/examples.
# The chart is Trustee's deployment/helm-chart at TRUSTEE_CHART_COMMIT with
# deploy/helm/trustee-chart.patch applied. deploy/helm/README.md gives the
# steps an Infrastructure Operator follows; this file runs the same steps.
# shellcheck shell=bash
# shellcheck disable=SC2154,SC2034 # trustee-cvm.sh sets work, gp, registry and the rest, and reads TRUSTEE_HOST, KBS_CONTAINER and endpoint

# Pinned here and not in versions.yaml: a change there gives the e2e guest
# image a new tag, and neither of these goes into the guest.
# docs/upstream-pins.md gives the source of each.
TRUSTEE_CHART_COMMIT=6b5fd14ef69d4ad634295f35a0759e2a3c7c7025
HELM_VERSION=v4.3.1
HELM_SHA256=0403a88ae20913d11b10a2467b50087721fea7581736da6b9d3992f5357fe54b

RELEASE=trustee
DEPLOY=trustee-kbs
SEL=app=kbs,app.kubernetes.io/instance=$RELEASE
TRUSTEE_SVC=trustee-kbs
TRUSTEE_HOST=$TRUSTEE_SVC.default.svc.cluster.local
KBS_CONTAINER=kbs
# The ReplicaSet names the pod; wait_live_pod sets this.
POD=

helm_tool() {
	helm=$E2E_CACHE/bin/helm-$HELM_VERSION
	[[ -x $helm ]] && return
	mkdir -p "${helm%/*}"
	curl -fsSLo "$helm.tar.gz" "https://get.helm.sh/helm-$HELM_VERSION-linux-amd64.tar.gz"
	echo "$HELM_SHA256  $helm.tar.gz" | sha256sum -c --quiet
	tar -xzf "$helm.tar.gz" -O linux-amd64/helm >"$helm.tmp"
	chmod +x "$helm.tmp"
	mv "$helm.tmp" "$helm"
	rm "$helm.tar.gz"
}

hc() {
	helm_tool
	[[ -s $work/kubeconfig ]] || kind get kubeconfig --name "$CLUSTER" >"$work/kubeconfig"
	"$helm" --kubeconfig "$work/kubeconfig" "$@"
}

# chart_dir: the patched chart, in a checkout of the pinned commit. Sets
# chart. The commit's hash names its content, so the fetch needs no sha256.
chart_dir() {
	local src=$E2E_CACHE/src/trustee-chart
	[[ -d $src/.git ]] || git init -q "$src"
	if ! git -C "$src" cat-file -e "$TRUSTEE_CHART_COMMIT^{commit}" 2>/dev/null; then
		info "fetching Trustee's Helm chart at $TRUSTEE_CHART_COMMIT"
		git -C "$src" fetch -q --depth 1 https://github.com/confidential-containers/trustee "$TRUSTEE_CHART_COMMIT"
	fi
	git -C "$src" checkout -q -f "$TRUSTEE_CHART_COMMIT"
	git -C "$src" apply "$repo/deploy/helm/trustee-chart.patch"
	chart=$src/deployment/helm-chart
	# Helm wants every dependency present, even disabled ones: the Bitnami
	# PostgreSQL and Valkey charts at the versions in Chart.lock.
	hc dependency build "$chart" >/dev/null
}

# live_pod: the release's KBS pod that is not terminating.
live_pod() {
	kc get pod -l "$SEL" -o go-template='{{range .items}}{{if not .metadata.deletionTimestamp}}{{.metadata.name}}{{"\n"}}{{end}}{{end}}'
}

wait_live_pod() {
	for _ in $(seq 90); do
		POD=$(live_pod 2>/dev/null | head -1)
		[[ -n $POD ]] && return
		sleep 2
	done
	die "no pod for deployment $DEPLOY"
}

# The negative checks apply a changed render with kubectl, as a host would,
# so remove_cvm deletes the Deployment as well as the release. apply_cvm
# sets POD to the new pod, so it must run in this shell, not in a pipeline.
apply_cvm() {
	kc apply -f - >/dev/null
	wait_live_pod
}

remove_cvm() {
	hc uninstall "$RELEASE" --ignore-not-found >/dev/null 2>&1 || true
	kc delete deployment "$DEPLOY" --ignore-not-found "${1:---wait}" >/dev/null
	[[ ${1:-} == --wait=false ]] || kc wait --for=delete pod -l "$SEL" --timeout=300s >/dev/null 2>&1 || true
}

# initdata_values <genpolicy output>: a values file that puts genpolicy's
# cc_init_data annotation on the chart's pod.
initdata_values() {
	python3 - "$1" <<-'EOF'
		import re, sys
		m = re.search(r'(\S*cc_init_data): *"?([A-Za-z0-9+/=]+)', open(sys.argv[1]).read())
		print(f'kbs:\n  podAnnotations:\n    {m.group(1)}: "{m.group(2)}"')
	EOF
}

# render_pod: render the chart, run genpolicy on the render, and pass the
# cc_init_data annotation back in through kbs.podAnnotations. The second
# render, $work/trustee-cvm.yaml, is what helm installs; it must differ from
# the first by that one line, or the policy describes another pod. genpolicy
# can't check this for us: given a pod that already carries the annotation,
# it reads it back and reorders the Init-Data's keys.
render_pod() {
	local manifest_sha256
	chart_dir
	manifest_sha256=$(sha256sum "$work/ceremony/ceremony.json" | cut -d' ' -f1)
	sed "s|@HELPER_IMAGE@|$helper_image|; s|@MANIFEST_SHA256@|$manifest_sha256|; s|@KBS_REPOSITORY@|${KBS_IMAGE%%:*}|; s|@KBS_TAG@|${KBS_IMAGE#*:}|" \
		"$repo/deploy/helm/sealed-cvm-values.yaml" >"$work/values.yaml"
	hc template "$RELEASE" "$chart" -f "$work/values.yaml" >"$work/render.yaml"
	# Kata 4.2.0's genpolicy panics on automountServiceAccountToken, which the
	# chart sets to false. Its settings allow the service-account mount
	# whatever the pod says, so the policy is the same without the field.
	sed '/^ *automountServiceAccountToken: false$/d' "$work/render.yaml" >"$work/genpolicy.yaml"
	"$gp/genpolicy" -y "$work/genpolicy.yaml" -p "$gp/rules.rego" -j "$gp" \
		--initdata-path="$work/init-data.toml" --insecure-registry="$registry" >/dev/null
	extract_initdata "$work/genpolicy.yaml" "$work/init.toml"
	initdata_values "$work/genpolicy.yaml" >"$work/initdata-values.yaml"
	hc template "$RELEASE" "$chart" -f "$work/values.yaml" -f "$work/initdata-values.yaml" >"$work/trustee-cvm.yaml"
	grep -v 'cc_init_data:' "$work/trustee-cvm.yaml" | diff - "$work/render.yaml" >"$work/render.diff" ||
		die "the second render differs from the first by more than the annotation: $(head -20 "$work/render.diff")"
}

deploy() {
	upload_inputs
	kc apply -f - <"$repo/deploy/helm/helper-service.yaml" >/dev/null
	hc install "$RELEASE" "$chart" -f "$work/values.yaml" -f "$work/initdata-values.yaml" >/dev/null
	wait_live_pod
	endpoint=$(helper_endpoint)
}

# check_recreate: kubectl rollout restart. With strategy Recreate, the old
# pod is gone before the new one exists. The new pod's helper waits for
# Shares, and Trustee serves nothing until then. The same Operator Policies
# unlock it, because it runs the same Init-Data and bundle.
check_recreate() {
	local old=$POD max=0 n new='' out holder
	kc rollout restart "deployment/$DEPLOY" >/dev/null
	for _ in $(seq 150); do
		n=$(kc get pod -l "$SEL" --no-headers 2>/dev/null | wc -l)
		((n > max)) && max=$n
		new=$(live_pod 2>/dev/null | head -1)
		if [[ -n $new && $new != "$old" ]] && ! kc get pod "$old" >/dev/null 2>&1; then break; fi
		sleep 1
	done
	[[ -n $new && $new != "$old" ]] || die "no new pod after the rollout"
	((max == 1)) || die "the rollout ran $max pods at once"
	POD=$new
	wait_helper
	status_is "COLLECTING []"
	[[ -z $(kc get endpointslice -l "kubernetes.io/service-name=$TRUSTEE_SVC" -o jsonpath='{.items[*].endpoints[?(@.conditions.ready==true)].addresses[*]}') ]] ||
		die "the $TRUSTEE_SVC Service routes to a pod that holds no Shares"
	info "recreate: the rollout ran one pod at a time; the new pod waits for Shares and $TRUSTEE_SVC routes nowhere"
	for holder in alice carol; do
		out=$(approve "$holder") || die "$holder's approve to the new pod: $out"
		[[ $out == accepted ]] || die "$holder's approve printed '$out'"
	done
	kc wait --for=condition=Ready "pod/$POD" --timeout=600s >/dev/null || die "the new pod did not become Ready"
	RESOURCE=$SECRET
	out=$(run_probe workload-again "$authorized")
	[[ $out == "$SECRET_VALUE" ]] || die "from the new pod, the workload got '$out'"
	kc delete pod workload-again --wait=false >/dev/null
	info "recreate: the same Operator Policies unlocked the new pod, and a workload got its key"
}
