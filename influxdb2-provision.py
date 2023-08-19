#!/usr/bin/env python3

import json
import sys
from typing import Any
from influxdb_client import Authorization, Bucket, InfluxDBClient, BucketRetentionRules, Organization, Permission, PermissionResource
from influxdb_client.rest import ApiException

all_perms = ["authorizations", "buckets", "dashboards", "orgs", "tasks", "telegrafs",
             "users", "variables", "secrets", "labels", "views", "documents",
             "notificationRules", "notificationEndpoints", "checks", "dbrp",
             "annotations", "sources", "scrapers", "notebooks", "remotes", "replications"]

def load_secret(filename):
    with open(filename, 'r') as f:
        return f.read().strip()

def main():
    if len(sys.argv) != 4:
        print("usage: python3 influxdb2-provision.py <state.json> <URL> <ADMIN_TOKEN>")
        sys.exit(1)

    with open(sys.argv[1], "r") as state_file:
        state = json.load(state_file)

    url = sys.argv[2]
    token = sys.argv[3]

    # Track changes to print a machine readable summary at the end
    changes = dict(users=[], orgs=[], buckets=[], auths=[])

    with InfluxDBClient(url=url, token=token) as client:
        # Initialize APIs
        buckets_api = client.buckets_api()
        orgs_api = client.organizations_api()
        users_api = client.users_api()
        auths_api = client.authorizations_api()

        try:
            known_auths = auths_api.find_authorizations()
        except ApiException as e:
            if e.status == 404:
                known_auths = []
            else:
                raise e

        try:
            known_orgs = {i.name: i for i in orgs_api.find_organizations()}
        except ApiException as e:
            if e.status == 404:
                known_orgs = {}
            else:
                raise e

        ######## Organizations

        def find_org(org_name):
            return known_orgs.get(org_name, None)

        def delete_org(org_name, org_data):
            if not org_data["present"]:
                if (org := find_org(org_name)) is not None:
                    orgs_api.delete_organization(org_id=org.id)
                    del known_orgs[org_name]
                    changes["orgs"].append(dict(action="deleted", name=org_name))
                    print(f"Deleted organization: {org_name}", file=sys.stderr)

        def create_or_update_org(org_name, org_data):
            def _update(org, org_data):
                if org_data["description"] is not None:
                    org.description = org_data["description"]
                return org

            if org_data["present"]:
                if (org := find_org(org_name)) is not None:
                    _update(org, org_data)
                    org = orgs_api.update_organization(org)
                else:
                    org = _update(Organization(name=org_name), org_data)
                    org = orgs_api.create_organization(organization=org)
                    known_orgs[org_name] = org
                    changes["orgs"].append(dict(action="created", name=org_name))
                    print(f"Created organization: {org_name}", file=sys.stderr)

        ######## Buckets

        def find_bucket(org_name, bucket_name):
            try:
                buckets = buckets_api.find_buckets(org=org_name, name=bucket_name)
            except ApiException as e:
                if e.status == 404:
                    return None
                raise e
            if buckets is None or len(buckets.buckets) == 0:
                return None
            return buckets.buckets[0]

        def delete_bucket(org_name, bucket_name, bucket_data):
            if not bucket_data["present"]:
                if (bucket := find_bucket(org_name, bucket_name)) is not None:
                    buckets_api.delete_bucket(bucket)
                    changes["buckets"].append(dict(action="deleted", org=org_name, name=bucket_name))
                    print(f"Deleted bucket: {org_name}.{bucket_name}", file=sys.stderr)

        def create_or_update_bucket(org_name, bucket_name, bucket_data):
            def _update(bucket, bucket_data):
                bucket.retention_rules = [BucketRetentionRules(every_seconds=int(bucket_data["retention"]))]
                if bucket_data["description"] is not None:
                    bucket.description = bucket_data["description"]
                return bucket

            if bucket_data["present"]:
                if (bucket := find_bucket(org_name, bucket_name)) is not None:
                    _update(bucket, bucket_data)
                    bucket = buckets_api.update_bucket(bucket)
                else:
                    bucket = _update(Bucket(name=bucket_name, retention_rules=[BucketRetentionRules()]), bucket_data)
                    bucket = buckets_api.create_bucket(org=org_name, bucket_name=bucket.name, description=bucket.description, retention_rules=bucket.retention_rules)
                    changes["buckets"].append(dict(action="created", org=org_name, name=bucket_name))
                    print(f"Created bucket: {org_name}.{bucket_name}", file=sys.stderr)

        ######## Auths

        def find_auth(id):
            for auth in known_auths:
                if id in auth.description:
                    return auth
            return None

        def delete_auth(org_name, auth_data):
            if not auth_data["present"]:
                if (auth := find_auth(auth_data["id"])) is not None:
                    auths_api.delete_authorization(auth)
                    changes["auths"].append(dict(action="deleted", org=org_name, id=auth_data["id"]))
                    print(f"Deleted auth: {auth.description}", file=sys.stderr)

        def create_or_update_auth(org_name, auth_name, auth_data):
            def _update(auth, auth_data):
                desc = f" - {auth_data['description']}" if auth_data['description'] is not None else ""
                auth.description = f"{auth_name}{desc} - {auth_data['id']}"
                auth.permissions = []
                if auth_data["operator"]:
                    # Assign general permissions
                    for perm in all_perms:
                        auth.permissions.append(Permission(action="read", resource=PermissionResource(type=perm)))
                    for perm in all_perms:
                        auth.permissions.append(Permission(action="write", resource=PermissionResource(type=perm)))
                else:
                    if auth_data["allAccess"]:
                        auth_data["readPermissions"] = all_perms
                        auth_data["writePermissions"] = all_perms

                    # Assign general permissions
                    for perm in auth_data["readPermissions"]:
                        org_id = None if perm in ["orgs", "users"] else auth.org_id
                        auth.permissions.append(Permission(action="read",
                                                           resource=PermissionResource(org_id=org_id, type=perm)))
                    for perm in auth_data["writePermissions"]:
                        org_id = None if perm in ["orgs", "users"] else auth.org_id
                        auth.permissions.append(Permission(action="write",
                                                           resource=PermissionResource(org_id=org_id, type=perm)))

                    # Assign bucket permissions
                    bucket_resources = {}
                    for bucket_name in set(auth_data["readBuckets"]) | set(auth_data["writeBuckets"]):
                        bucket = find_bucket(org_name, bucket_name)
                        assert bucket is not None
                        bucket_resources[bucket_name] = PermissionResource(org_id=auth.org_id, type="buckets", id=bucket.id)
                    for bucket_name in auth_data["readBuckets"]:
                        auth.permissions.append(Permission(action="read", resource=bucket_resources[bucket_name]))
                    for bucket_name in auth_data["writeBuckets"]:
                        auth.permissions.append(Permission(action="write", resource=bucket_resources[bucket_name]))
                return auth

            if auth_data["present"]:
                if (auth := find_auth(auth_data["id"])) is not None:
                    pass # No updateable attributes
                else:
                    org = find_org(org_name)
                    assert org is not None
                    auth = _update(Authorization(org_id=org.id), auth_data)
                    auth = auths_api.create_authorization(authorization=auth)
                    changes["auths"].append(dict(action="created", org=org_name, id=auth_data["id"]))
                    print(f"Created auth: {auth.description}", file=sys.stderr)

        ######## Users

        def find_user(user_name):
            try:
                users: Any = users_api.find_users(name=user_name)
            except ApiException as e:
                if e.status == 404:
                    return None
                raise e
            if users is None or len(users.users) == 0:
                return None
            return users.users[0]

        def delete_user(user_name, user_data):
            if not user_data["present"]:
                if (user := find_user(user_name)) is not None:
                    users_api.delete_user(user)
                    changes["users"].append(dict(action="deleted", name=user_name))
                    print(f"Deleted user: {user_name}", file=sys.stderr)

        def create_or_update_user(user_name, user_data):
            if user_data["present"]:
                if (user := find_user(user_name)) is not None:
                    pass # No updateable attributes
                else:
                    user = users_api.create_user(name=user_name)
                    changes["users"].append(dict(action="created", name=user_name))
                    print(f"Created user: {user_name}", file=sys.stderr)
                users_api.update_password(user, load_secret(user_data["passwordFile"]))

        ######## Provisioning

        # Delete users
        for user_name, user_data in state["users"].items():
            delete_user(user_name, user_data)

        # Delete organizations
        for org_name, org_data in state["organizations"].items():
            for bucket_name, bucket_data in org_data["buckets"].items():
                delete_bucket(org_name, bucket_name, bucket_data)
            # XXX: remotes
            # XXX:   replications
            for _, auth_data in org_data["auths"].items():
                delete_auth(org_name, auth_data)
            delete_org(org_name, org_data)

        # Create organizations
        for org_name, org_data in state["organizations"].items():
            create_or_update_org(org_name, org_data)
            if org_data["present"]:
                for bucket_name, bucket_data in org_data["buckets"].items():
                    create_or_update_bucket(org_name, bucket_name, bucket_data)
                # XXX: remotes
                # XXX:   replications
                for auth_name, auth_data in org_data["auths"].items():
                    create_or_update_auth(org_name, auth_name, auth_data)

        # Create users
        for user_name, user_data in state["users"].items():
            create_or_update_user(user_name, user_data)

        print(json.dumps(changes))

if __name__ == "__main__":
    main()
