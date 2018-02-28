import { APIResource } from '../store/types/api.types';

export interface IRoute {
  host: string;
  path: string;
  domain_guid: string;
  space_guid: string;
  service_instance_guid?: any;
  port?: any;
  domain_url: string;
  domain: IDomain;
  space_url: string;
  space: APIResource<ISpace>;
  apps_url: string;
  apps: APIResource<IApp>[];
  route_mappings_url: string;
  guid: string;
  cfGuid: string;
}

export interface ISpace {
  name: string;
  organization_guid: string;
  space_quota_definition_guid?: any;
  isolation_segment_guid?: any;
  allow_ssh: boolean;
  organization_url: string;
  organization: IOrganization;
  developers_url: string;
  developers: IDeveloper[];
  managers_url: string;
  managers: IDeveloper[];
  auditors_url: string;
  auditors: any[];
  apps_url: string;
  apps: APIResource<IApp>[];
  routes_url: string;
  domains_url: string;
  domains: IDomain[];
  service_instances_url: string;
  service_instances: any[];
  app_events_url: string;
  events_url: string;
  security_groups_url: string;
  security_groups: ISecurityGroup[];
  staging_security_groups_url: string;
  staging_security_groups: ISecurityGroup[];
  space_quota_definition?: APIResource<IQuotaDefinition>;
  routes?: APIResource<IRoute>[];
  guid: string;
  cfGuid: string;
}

export interface ISecurityGroup {
  name: string;
  rules: IRule[];
  running_default: boolean;
  staging_default: boolean;
  spaces_url: string;
  staging_spaces_url: string;
}

export interface IRule {
  destination: string;
  protocol: string;
  ports?: string;
}

export interface IApp {
  name: string;
  production?: boolean;
  space_guid: string;
  stack_guid?: string;
  buildpack?: any;
  detected_buildpack?: string;
  detected_buildpack_guid?: string;
  environment_json?: IEnvironmentjson;
  memory?: number;
  instances?: number;
  disk_quota?: number;
  state?: string;
  version?: string;
  command?: any;
  console?: boolean;
  debug?: any;
  staging_task_id?: string;
  package_state?: string;
  health_check_type?: string;
  health_check_timeout?: any;
  health_check_http_endpoint?: any;
  staging_failed_reason?: any;
  staging_failed_description?: any;
  diego?: boolean;
  docker_image?: any;
  docker_credentials?: IDockercredentials;
  package_updated_at?: string;
  detected_start_command?: string;
  allow_ssh?: boolean;
  ports?: number[];
  space_url?: string;
  stack_url?: string;
  routes_url?: string;
  events_url?: string;
  service_bindings_url?: string;
  route_mappings_url?: string;
}

export interface IDockercredentials {
  username?: any;
  password?: any;
}

export interface IEnvironmentjson {
  [any: string]: string;
}

export interface IDeveloper {
  admin: boolean;
  active: boolean;
  default_space_guid?: any;
  spaces_url: string;
  organizations_url: string;
  managed_organizations_url: string;
  billing_managed_organizations_url: string;
  audited_organizations_url: string;
  managed_spaces_url: string;
  audited_spaces_url: string;
}

export interface IOrganization {
  name: string;
  billing_enabled: boolean;
  quota_definition_guid: string;
  status: string;
  default_isolation_segment_guid?: any;
  quota_definition_url: string;
  spaces_url: string;
  domains_url: string;
  private_domains_url: string;
  users_url: string;
  managers_url: string;
  billing_managers_url: string;
  auditors_url: string;
  app_events_url: string;
  space_quota_definitions_url: string;
  guid: string;
  cfGuid: string;
  spaces?: APIResource<ISpace>[];
  private_domains?: APIResource<IPrivateDomain>[];
  quota_definition?: APIResource<IQuotaDefinition>;
}

export interface IDomain {
  name: string;
  router_group_guid?: any;
  router_group_type?: any;
}

export interface IServiceInstance {
  guid: string;
  cfGuid: string;
}

export interface IPrivateDomain {
  guid: string;
  cfGuid: string;
}

export interface IQuotaDefinition {
  memory_limit: number;
  app_instance_limit: number;
  instance_memory_limit: number;
  name: string;
  organization_guid?: string;
  total_services?: number;
  total_routes?: number;
  total_private_domains?: number;
}


export interface IUpdateSpace {
  name?: string;
  organization_guid?: string;
  developer_guids?: string[];
  manager_guids?: string[];
  auditor_guids?: string[];
  domain_guids?: string[];
  security_group_guids?: string[];
  allow_ssh?: boolean;
  isolation_segment_guid?: string;
}
