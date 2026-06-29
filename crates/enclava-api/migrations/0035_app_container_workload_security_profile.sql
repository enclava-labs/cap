ALTER TABLE app_containers
  ADD COLUMN workload_security_profile text;

ALTER TABLE app_containers
  ADD CONSTRAINT app_containers_workload_security_profile_check
  CHECK (
    workload_security_profile IS NULL
    OR workload_security_profile IN ('restricted', 'platform-managed-ssh-relay')
  );
