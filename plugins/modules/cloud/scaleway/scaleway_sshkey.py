#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Scaleway SSH keys management module
#
# Copyright (C) 2022 Michaël PAULON <michael+ansible@paulon.org>
# Copyright (C) 2018 Online SAS.
# https://www.scaleway.com
#
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = '''
---
module: scaleway_sshkey
short_description: Scaleway SSH keys management module
author: Remy Leone (@remyleone)
description:
    - This module manages SSH keys on Scaleway account
      U(https://developer.scaleway.com)
extends_documentation_fragment:
- community.general.scaleway


options:
  name:
    type: str
    description:
      - Name of the SSH key
  state:
    type: str
    description:
     - Indicate desired state of the SSH key.
    default: present
    choices:
      - present
      - absent
  ssh_pub_key:
    type: str
    description:
     - The public SSH key as a string to add.
    required: true
  project:
    type: str
    description:
      - Project identifier.
'''

EXAMPLES = '''
- name: "Add SSH key named example"
  community.general.scaleway_sshkey:
    name: example
    ssh_pub_key: "ssh-rsa AAAA..."
    state: "present"
    project: 951df375-e094-4d26-97c1-ba548eeb9c42

- name: "Delete SSH key"
  community.general.scaleway_sshkey:
    name: example
    ssh_pub_key: "ssh-rsa AAAA..."
    state: "absent"
    project: 951df375-e094-4d26-97c1-ba548eeb9c42
'''

RETURN = '''
data:
    description: This is only present when C(state=present)
    returned: when C(state=present)
    type: dict
    sample: {
        "ssh_public_keys": [
            {"key": "ssh-rsa AAAA...."}
        ]
    }
'''

from ansible.module_utils.basic import AnsibleModule, env_fallback
from ansible_collections.community.general.plugins.module_utils.scaleway import scaleway_argument_spec, Scaleway

def extract_matching_keys(sshkeys_json, name, key, project):
    return {
        k["id"]: (k["name"], k["public_key"]) for k in sshkeys_json["ssh_keys"] if
        (k["name"] == name or k["public_key"] == key) and k["project_id"] == project
    }

def core(module):
    key_state = module.params["state"]
    key = module.params["ssh_pub_key"]
    name = module.params["name"]
    project = module.params["project"]

    ENDPOINT = "account/v2alpha1/ssh-keys"
    api = Scaleway(module=module)

    response  = api.get(ENDPOINT)
    sshkeys_json = response.json

    if not response.ok:
        module.fail_json(msg='Error getting ssh keys [{0}: {1}]'.format(
            response.status_code, response.json['message']))

    try:
        matching_keys = extract_matching_keys(sshkeys_json, name=name, key=key, project=project)
    except (KeyError, IndexError) as e:
        module.fail_json(msg="Error while extracting present SSH keys from API")

    if key_state == "present":
        if (name, key) in list(matching_keys.values()):
            module.exit_json(changed=False)
        else:
            if module.check_mode:
                module.exit_json(changed=True)
            data = {
                "name": name,
                "public_key": key,
                "project_id": project
            }

            response = api.post(ENDPOINT, data=data)
            if response.ok:
                module.exit_json(changed=True, msg=response.json)
            module.fail_json(msg='Error creating ssh key [{0}: {1}]'.format(
                response.status_code, response.json))
        
        # TODO: add feature to update keys

    if key_state == "absent":
        if (name, key) in list(matching_keys.values()):
            if module.check_mode:
                module.exit_json(changed=True)
            id = matching_keys.keys()[matching_keys.values().index((name, key))]
            response = api.delete("{}/{}".format(ENDPOINT, id))
            if response.ok:
                module.exit_json(changed=True, data=response.json)
            module.fail_json(msg='Error deleting ssh key [{0}: {1}]'.format(
                response.status_code, response.json))
        else:
            module.exit_json(changed=False)

    module.fail_json(msg='Invalid state {}'.format(key_state))    

def main():
    argument_spec = scaleway_argument_spec()
    argument_spec.update(dict(
        state=dict(choices=['absent', 'present'], default='present'),
        ssh_pub_key=dict(),
        name=dict(),
        project=dict(required=True),
    ))
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_one_of=[
            ('name', 'ssh_pub_key'),
        ],
        required_if=[
            ('state', 'present', ('name', 'ssh_pub_key'))
        ]
    )
    core(module)


if __name__ == '__main__':
    main()
