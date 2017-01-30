#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import time

from neutronclient.common import exceptions as neutron_exceptions
from oslo_config import cfg
from oslo_log import log

from ironic_inspector.common import neutron
from ironic_inspector.common.i18n import _, _LI
from ironic_inspector import utils


CONF = cfg.CONF

LOG = utils.getProcessingLogger(__name__)




# TODO(add base DHCP)
class NeutronDHCP(object):
    """API for updating dhcp options via Neutron v2 API."""

    def update_dhcp_opts(self, node, options, vifs=None):
        """Send or update the DHCP BOOT options for this node.

        :param node: A NodeInfo instance.
        :param options: this will be a list of dicts, e.g.

                        ::

                         [{'opt_name': 'bootfile-name',
                           'opt_value': 'pxelinux.0'},
                          {'opt_name': 'server-ip-address',
                           'opt_value': '123.123.123.456'},
                          {'opt_name': 'tftp-server',
                           'opt_value': '123.123.123.123'}]
        :param vifs: a dict of Neutron port/portgroup dicts
                     to update DHCP options on. The port/portgroup dict
                     key should be Ironic port UUIDs, and the values
                     should be Neutron port UUIDs, e.g.

                     ::

                      {'ports': {'port.uuid': vif.id},
                       'portgroups': {'portgroup.uuid': vif.id}}
                      If the value is None, will get the list of
                      ports/portgroups from the Ironic port/portgroup
                      objects.
        """
        if vifs is None:
            vifs = [node._vifs]
        if not vifs:
            raise utils.FailedToUpdateDHCPOptOnPort(
                _("No VIFs found for node %(node)s when attempting "
                  "to update DHCP BOOT options.") %
                {'node': task.node.uuid})

        failures = []
        
        for vif in vifs:
            try:
                self.update_port_dhcp_opts(vif, options)
            except utils.FailedToUpdateDHCPOptOnPort:
                failures.append(vif)

        if failures:
            if len(failures) == len(vif_list):
                raise utils.FailedToUpdateDHCPOptOnPort(_(
                    "Failed to set DHCP BOOT options for any port on node %s.")
                    % node.uuid)
            else:
                LOG.warning(_LW("Some errors were encountered when updating "
                                "the DHCP BOOT options for node %(node)s on "
                                "the following Neutron ports: %(ports)s."),
                            {'node': node.uuid, 'ports': failures})

        port_delay = CONF.neutron.port_setup_delay
        if port_delay != 0:
            LOG.debug("Waiting %d seconds for Neutron.", port_delay)
            time.sleep(port_delay)

    def update_port_dhcp_opts(self, port_id, dhcp_options):
        """Update a port's attributes.

        Update one or more DHCP options on the specified port.
        For the relevant API spec, see
        http://docs.openstack.org/api/openstack-network/2.0/content/extra-dhc-opt-ext-update.html

        :param port_id: designate which port these attributes
                        will be applied to.
        :param dhcp_options: this will be a list of dicts, e.g.

                             ::

                              [{'opt_name': 'bootfile-name',
                                'opt_value': 'pxelinux.0'},
                               {'opt_name': 'server-ip-address',
                                'opt_value': '123.123.123.456'},
                               {'opt_name': 'tftp-server',
                                'opt_value': '123.123.123.123'}]
        :param token: optional auth token.

        :raises: FailedToUpdateDHCPOptOnPort
        """
        port_req_body = {'port': {'extra_dhcp_opts': dhcp_options}}
        try:
            neutron.get_client().update_port(port_id, port_req_body)
        except  neutron_exceptions.NeutronClientException:
            LOG.exception(_LE("Failed to update Neutron port %s."), port_id)
            raise utils.FailedToUpdateDHCPOptOnPort(port_id=port_id)


    def add_introspection_ports(self, node):
        """Add the introspection port for the node.

        :param node: A NodeInfo object.
        :raises: NetworkError
        """
        LOG.info(_LI('Adding introspection port to node %s'),
                 node.uuid)
        vifs = neutron.add_ports_to_network(
            node, CONF.neutron.introspection_network)

        for address, port in node.ports().items():
            if port.uuid in vifs:
                node._vifs = vifs[port.uuid]
        


