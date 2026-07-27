# Railway CLI version sentinel

The production deployment workflow downloads Railway's official Linux release binary
directly and verifies its published SHA-256 before execution. This isolated manifest
exists only so Dependabot can propose reviewed Railway CLI upgrades without adding the
CLI or its installer dependencies to SecURL's application lockfile.

When Dependabot proposes an upgrade:

1. review the Railway CLI release notes and official GitHub release;
2. update the workflow's `RAILWAY_CLI_VERSION`;
3. copy the SHA-256 for the exact `x86_64-unknown-linux-gnu` asset from that release into
   `RAILWAY_CLI_SHA256`;
4. verify the downloaded archive against that digest and run the deployment smoke path;
5. keep install scripts denied here—the npm wrapper is not executed by SecURL.
