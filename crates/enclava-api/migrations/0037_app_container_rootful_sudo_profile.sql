ALTER TABLE app_containers
  DROP CONSTRAINT app_containers_workload_security_profile_check;

ALTER TABLE app_containers
  ADD CONSTRAINT app_containers_workload_security_profile_check
  CHECK (
    workload_security_profile IS NULL
    OR workload_security_profile IN ('restricted', 'platform-managed-ssh-relay', 'rootful-sudo')
  );
