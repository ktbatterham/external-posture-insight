export function createTelemetryTracker() {
  const startedAt = new Date().toISOString();

  const state = {
    pageLoads: 0,
    scansRequested: 0,
    scansCompleted: 0,
    fullReads: 0,
    limitedReads: 0,
    quietModeScans: 0,
    limitedReadKinds: {},
    failureClasses: {},
    authRejected: 0,
    requesterRateLimited: 0,
    targetRateLimited: 0,
  };

  const incrementBucket = (bucket, key) => {
    bucket[key] = (bucket[key] ?? 0) + 1;
  };

  return {
    recordPageLoad() {
      state.pageLoads += 1;
    },
    recordScanRequested({ mode }) {
      state.scansRequested += 1;
      if (mode === "quiet") {
        state.quietModeScans += 1;
      }
    },
    recordScanCompleted(result) {
      state.scansCompleted += 1;
      if (result.assessmentLimitation?.limited) {
        state.limitedReads += 1;
        incrementBucket(state.limitedReadKinds, result.assessmentLimitation.kind || "unknown");
      } else {
        state.fullReads += 1;
      }
    },
    recordFailure(failureClass) {
      incrementBucket(state.failureClasses, failureClass);
    },
    recordAuthRejected() {
      state.authRejected += 1;
    },
    recordRequesterRateLimited() {
      state.requesterRateLimited += 1;
    },
    recordTargetRateLimited() {
      state.targetRateLimited += 1;
    },
    snapshot() {
      return {
        startedAt,
        persistence: "memory",
        pageLoads: state.pageLoads,
        scans: {
          requested: state.scansRequested,
          completed: state.scansCompleted,
          fullReads: state.fullReads,
          limitedReads: state.limitedReads,
          quietMode: state.quietModeScans,
          limitedReadKinds: { ...state.limitedReadKinds },
        },
        failures: {
          classes: { ...state.failureClasses },
          authRejected: state.authRejected,
          requesterRateLimited: state.requesterRateLimited,
          targetRateLimited: state.targetRateLimited,
        },
      };
    },
  };
}

export function classifyScanFailure(error) {
  const message = String(error?.message ?? error ?? "").toLowerCase();

  if (!message || message.includes("enter a url")) {
    return "invalid_target_empty";
  }
  if (message.includes("embedded credentials")) {
    return "invalid_target_credentials";
  }
  if (message.includes("localhost") || message.includes("private network") || message.includes("public ip")) {
    return "invalid_target_private";
  }
  if (message.includes("only http and https")) {
    return "invalid_target_protocol";
  }
  if (message.includes("resolve to a public ip")) {
    return "invalid_target_resolution";
  }

  return "scan_runtime_failure";
}
