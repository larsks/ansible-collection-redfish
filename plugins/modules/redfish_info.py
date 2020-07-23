import logging
import os
import requests

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.oddbit_dot_com.redfish.plugins.module_utils.redfish import Redfish, RedfishError

LOG = logging.getLogger()

default_rf_username = os.environ.get('REDFISH_USERNAME')
default_rf_password = os.environ.get('REDFISH_PASSWORD')


def main():
    module = AnsibleModule(
        argument_spec=dict(
            baseuri=dict(required=True),
            resource=dict(),
            ref=dict(type='dict'),
            username=dict(required=False, default=default_rf_username),
            password=dict(required=False, default=default_rf_password,
                          no_log=True),
            resolve=dict(type='list', default=[]),
            tls_verify=dict(required=False, default=True, type='bool'),
            tls_ca=dict(required=False),
            timeout=dict(required=False, type='int'),
        )
    )

    resource = module.params.get('resource')
    ref = module.params.get('ref')

    try:
        if ref:
            resource = ref['@odata.id']
    except KeyError:
        module.fail_jason(msg='Ref is not in expected format')

    if not ref and not resource:
        module.fail_jason(msg='You must provide either ref or resource')

    if module.params['tls_verify']:
        if module.params.get('tls_ca'):
            tls_verify = module.params['tls_ca']
        else:
            tls_verify = True
    else:
        tls_verify = False

    try:
        sess = Redfish(module.params['baseuri'],
                       verify=tls_verify,
                       timeout=module.params.get('timeout'))
        sess.auth = (module.params['username'], module.params['password'])

        info = sess.get_resource(resource)
        sess.resolve(info, module.params['resolve'])
    except RedfishError as err:
        module.fail_json(msg=str(err))
    else:
        module.exit_json(resource=module.params['resource'],
                         result=info)


if __name__ == '__main__':
    main()
