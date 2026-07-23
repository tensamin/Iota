use iota_daemon_lib::{DaemonRuntime, StartupPhase};
use iota_ipc::{ComponentId, HealthStatus, LifecyclePhase};

#[test]
fn component_failures_are_independent_and_recovery_is_scoped() {
    let runtime = DaemonRuntime::new();
    runtime.set_component_degraded(ComponentId::Omikron, "offline".into());
    runtime.set_component_failed(ComponentId::Web, "bind failed".into());
    runtime.set_startup_phase(StartupPhase::Ready);
    let snapshot = runtime.snapshot();
    assert_eq!(snapshot.lifecycle, LifecyclePhase::Ready);
    assert_eq!(snapshot.overall_health, HealthStatus::Degraded);
    assert_eq!(
        snapshot.components[&ComponentId::Omikron].status,
        HealthStatus::Degraded
    );
    runtime.set_component_healthy(ComponentId::Web, None);
    assert_eq!(
        runtime.snapshot().components[&ComponentId::Omikron].status,
        HealthStatus::Degraded
    );
}

#[test]
fn critical_failure_is_failed_but_optional_degradation_is_not() {
    let runtime = DaemonRuntime::new();
    runtime.set_component_failed(ComponentId::Storage, "database unavailable".into());
    assert_eq!(runtime.snapshot().overall_health, HealthStatus::Failed);
}
