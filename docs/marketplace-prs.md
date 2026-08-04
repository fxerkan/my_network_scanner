coollabsio / coolify

https://github.com/coollabsio/coolify/pull/11124#issuecomment-5180996337 

This PR did not pass quality checks so it will be closed. If you believe this is a mistake please let us know.

Result	Check	Details
❌	target-branch	Target branch "v4.x" is not allowed
❌	pr-template	Missing section(s): "Changes", "Category", "AI Assistance", "Testing", "Contributor Agreement"
❌	strict-pr-template-sections	Strict section "Contributor Agreement" is missing from the PR description
❌	max-added-comments	Found 11 added comment(s), exceeding the limit of 10

-----


Portainer Templates

@lissy93 commented on this pull request.

I think this is invalid. The sources.csv is to track upstream collections of portainer templates. And this one just has one template in.

https://github.com/lissy93/portainer-templates/pull/127?email_source=notifications&email_token=AE6UPOOQLBCABAOOO7CMTLT5IH6LVA5CNFSNUABKM5UWIORPF5TWS5BNNB2WEL2QOVWGYUTFOF2WK43UKJSXM2LFO4XTIOBVGYZDCMBYG432M4TFMFZW63VGMF2XI2DPOKSWK5TFNZ2KYZTPN52GK4S7MNWGSY3L#pullrequestreview-4856210877

----

Umbrel-apps

 Lint failing https://github.com/getumbrel/umbrel-apps/actions/runs/30923160881/job/92038652080

 Error: `releaseNotes` must be empty for new app submissions.
Warning: Leave `gallery: []` for new official App Store submissions; Umbrel will create final gallery assets.
Warning: Service `server` uses host networking; justify this in the PR.
Warning: Service `server` adds Linux capabilities; justify this in the PR.
Error: Bind mount source `${APP_DATA_DIR}/data` is not committed at `mynes/data`.
Error: Bind mount source `${APP_DATA_DIR}/config` is not committed at `mynes/config`.
Warning: Do not commit App Store screenshots, gallery assets, or icon/logo assets; include them in the PR body instead.
Error: Process completed with exit code 1.

-----


fxerkan/mynes-casaos-store 

https://github.com/fxerkan/mynes-casaos-store/actions/runs/30921251774/job/92032141589

Fail if build failed
0s
Run set -euo pipefail
  AppStore build failed.
  Error: Process completed with exit code 1.

---------

