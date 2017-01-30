# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from neutronclient.common import exceptions as neutron_exceptions
from neutronclient.v2_0 import client as clientv20
from oslo_config import cfg

from ironic_inspector.common.i18n import _, _LW, _LI
from ironic_inspector.common import keystone
from ironic_inspector import utils

CONF = cfg.CONF
LOG = utils.getProcessingLogger(__name__)


NEUTRON_GROUP = 'neutron'

NEUTRON_OPTS = [
    cfg.StrOpt('neutron_url',
               help=_('Neutron url.')),
    cfg.StrOpt('auth_strategy',
               default='keystone',
               choices=['keystone', 'noauth'],
               help=_('Authentication strategy to use when connecting to '
                      'neutron. Running neutron in noauth mode (related to '
                      'but not affected by this setting) is insecure and '
                      'should only be used for testing.')),
    cfg.StrOpt('os_region',
               help=_('Keystone region used to get Ironic endpoints.')),
    cfg.StrOpt('os_service_type',
               default='baremetal',
               help=_('Ironic service type.')),
    cfg.StrOpt('os_endpoint_type',
               default='internalURL',
               help=_('Ironic endpoint type.')),
    cfg.IntOpt('port_setup_delay',
               default=0,
               min=0,
               help=_('Delay value to wait for Neutron agents to setup '
                      'sufficient DHCP configuration for port.')),
    # TODO(aarefiev): move to separate group
    cfg.StrOpt('introspection_network',
               help=_('Neutron network UUID or name for the ramdisk to be '
                      'booted into for introspecting nodes. If a name is provided, '
                      'it must be unique among all networks or introspection will '
                      'fail.')),
    cfg.StrOpt('pxe_boot_file',
               default='undionly.kpxe',
               help=_('Bootfile DHCP parameter.')),
    cfg.StrOpt('ipxe_boot_script',
               help=_('The path to the iPXE script file.')),
    cfg.StrOpt('tftp_server',
               help=_("IP address of ironic-conductor node's TFTP server.")),

]


CONF.register_opts(NEUTRON_OPTS, group=NEUTRON_GROUP)
keystone.register_auth_opts(NEUTRON_GROUP)

NEUTRON_SESSION = None


def get_client(token=None):
    """Get Neutron client instance."""
    if CONF.neutron.auth_strategy == 'noauth':
        args = {'token': 'noauth',
                'endpoint': CONF.neutron.neutron_url}
    else:
        global NEUTRON_SESSION
        if not NEUTRON_SESSION:
            NEUTRON_SESSION = keystone.get_session(NEUTRON_GROUP)
        if token is None:
            args = {'session': NEUTRON_SESSION,
                    'region_name': CONF.neutron.os_region}
        else:
            neutron_url = NEUTRON_SESSION.get_endpoint(
                service_type=CONF.neutron.os_service_type,
                endpoint_type=CONF.neutron.os_endpoint_type,
                region_name=CONF.neutron.os_region
            )
            args = {'token': token,
                    'endpoint': neutron_url}
    args['timeout'] = CONF.neutron.timeout
    return clientv20.Client(**args)
    


def add_ports_to_network(node, network_uuid):
    """Create neutron ports to boot the ramdisk.

    Create neutron ports for each pxe_enabled port on node to boot
    the ramdisk.

    :param network_uuid: UUID of a neutron network where ports will be
        created.
    :raises: NetworkError
    :returns: a dictionary in the form {port.uuid: neutron_port['id']}
    """
    client = get_client()

    LOG.debug('For node %(node)s, creating neutron ports on network '
              '%(network_uuid)s.',
              {'node': node.uuid, 'network_uuid': network_uuid})
    body = {
        'port': {
            'network_id': network_uuid,
            'admin_state_up': True,
            'binding:vnic_type': 'baremetal',
            'device_owner': 'baremetal:none',
            'device_id': node.uuid
        }
    }

    ports = {}
    failures = []
    ironic_ports = node.ports()
    pxe_enabled_ports = {a: p for a, p in ironic_ports.items() if p.pxe_enabled}
    for address, ironic_port in pxe_enabled_ports.items():
        body['port']['mac_address'] = address
        binding_profile = {'local_link_information':
                           [ironic_port.local_link_connection]}
        body['port']['binding:profile'] = binding_profile
        client_id = ironic_port.extra.get('client-id')
        if client_id:
            client_id_opt = {'opt_name': 'client-id', 'opt_value': client_id}
            extra_dhcp_opts = body['port'].get('extra_dhcp_opts', [])
            extra_dhcp_opts.append(client_id_opt)
            body['port']['extra_dhcp_opts'] = extra_dhcp_opts
        try:
            port = client.create_port(body)
        except neutron_exceptions.NeutronClientException as e:
            # no port uuid?
            failures.append(ironic_port.uuid)
            LOG.warning(_LW("Could not create neutron port for node's "
                            "%(node)s port %(ir-port)s on the neutron "
                            "network %(net)s. %(exc)s"),
                        {'net': network_uuid, 'node': node.uuid,
                         'ir-port': ironic_port.uuid, 'exc': e})
        else:
            ports[ironic_port.uuid] = port['port']['id']

    if failures:
        if len(failures) == len(pxe_enabled_ports):
            rollback_ports(node, network_uuid)
            raise utils.NetworkError(_(
                "Failed to create neutron ports for any PXE enabled port "
                "on node %s.") % node.uuid)
        else:
            LOG.warning(_LW("Some errors were encountered when updating "
                            "vif_port_id for node %(node)s on "
                            "the following ports: %(ports)s."),
                        {'node': node.uuid, 'ports': failures})
    else:
        LOG.info(_LI('Successfully created ports for node %(node_uuid)s in '
                     'network %(net)s.'),
                 {'node_uuid': node.uuid, 'net': network_uuid})

    return ports


def remove_neutron_ports(node, params):
    """Deletes the neutron ports matched by params.

    :param node: a NodeInfo instance.
    :param params: Dict of params to filter ports.
    :raises: NetworkError
    """
    client = get_client()
    try:
        response = client.list_ports(**params)
    except neutron_exceptions.NeutronClientException as e:
        msg = (_('Could not get given network VIF for %(node)s '
                 'from neutron, possible network issue. %(exc)s') %
               {'node': node.uuid, 'exc': e})
        LOG.exception(msg)
        raise utils.NetworkError(msg)

    ports = response.get('ports', [])
    if not ports:
        LOG.debug('No ports to remove for node %s', node.uuid)
        return

    for port in ports:
        LOG.debug('Deleting neutron port %(vif_port_id)s of node '
                  '%(node_id)s.',
                  {'vif_port_id': port['id'], 'node_id': node.uuid})

        try:
            client.delete_port(port['id'])
        except neutron_exceptions.NeutronClientException as e:
            msg = (_('Could not remove VIF %(vif)s of node %(node)s, possibly '
                     'a network issue: %(exc)s') %
                   {'vif': port['id'], 'node': node.uuid, 'exc': e})
            LOG.exception(msg)
            raise utils.NetworkError(msg)

    LOG.info(_LI('Successfully removed node %(node_uuid)s neutron ports.'),
             {'node_uuid': node.uuid})


def rollback_ports(node, network_uuid):
    """Attempts to delete any ports created for introspection

    Purposefully will not raise any exceptions so error handling can
    continue.

    :param node: NodeInfo instance.
    :param network_uuid: UUID of a neutron network.
    """
    ironic_ports = node.ports()
    macs = [a for a, p in ironic_ports.items() if p.pxe_enabled]
    if macs:
        params = {
            'network_id': network_uuid,
            'mac_address': macs,
        }
        LOG.debug("Removing ports on network %(net)s on node %(node)s.",
                  {'net': network_uuid, 'node': node.uuid})

    try:
        remove_neutron_ports(node, params)


    except utils.NetworkError:
        # Only log the error
        LOG.exception(_LE(
            'Failed to rollback port changes for node %(node)s '
            'on network %(network)s'), {'node': node.uuid,
                                        'network': network_uuid})


def list_opts():
    return keystone.add_auth_options(NEUTRON_OPTS, NEUTRON_GROUP)
