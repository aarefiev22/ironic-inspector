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

import eventlet
eventlet.monkey_patch()

import datetime
import time

import contextlib
import copy
import json
import os
import pytz
import shutil
import six
from six.moves import urllib
import tempfile
import unittest

import mock
from oslo_config import cfg
from oslo_config import fixture as config_fixture
from oslo_utils import timeutils
import requests

from ironic_inspector.common import ironic as ir_utils
from ironic_inspector.common import swift
from ironic_inspector import db
from ironic_inspector import dbsync
from ironic_inspector import introspection_state as istate
from ironic_inspector import main
from ironic_inspector import node_cache
from ironic_inspector import rules
from ironic_inspector.test import base


CONF = """
[ironic]
os_auth_url = http://url
os_username = user
os_password = password
os_tenant_name = tenant
[firewall]
manage_firewall = False
[processing]
enable_setting_ipmi_credentials = True
[DEFAULT]
debug = True
auth_strategy = noauth
[database]
connection = sqlite:///%(db_file)s
"""


DEFAULT_SLEEP = 2
TEST_CONF_FILE = None


def get_test_conf_file():
    global TEST_CONF_FILE
    if not TEST_CONF_FILE:
        d = tempfile.mkdtemp()
        TEST_CONF_FILE = os.path.join(d, 'test.conf')
        db_file = os.path.join(d, 'test.db')
        with open(TEST_CONF_FILE, 'wb') as fp:
            content = CONF % {'db_file': db_file}
            fp.write(content.encode('utf-8'))
    return TEST_CONF_FILE


def get_error(response):
    return response.json()['error']['message']


def _query_string(*field_names):
    def outer(func):
        @six.wraps(func)
        def inner(*args, **kwargs):
            queries = []
            for field_name in field_names:
                field = kwargs.pop(field_name, None)
                if field is not None:
                    queries.append('%s=%s' % (field_name, field))

            query_string = '&'.join(queries)
            if query_string:
                query_string = '?' + query_string
            return func(*args, query_string=query_string, **kwargs)
        return inner
    return outer


class Base(base.NodeTest):
    ROOT_URL = 'http://127.0.0.1:5050'
    IS_FUNCTIONAL = True

    def setUp(self):
        super(Base, self).setUp()
        rules.delete_all()

        self.cli = ir_utils.get_client()
        self.cli.reset_mock()
        self.cli.node.get.return_value = self.node
        self.cli.node.update.return_value = self.node
        self.cli.node.list.return_value = [self.node]

        self.patch = [
            {'op': 'add', 'path': '/properties/cpus', 'value': '4'},
            {'path': '/properties/cpu_arch', 'value': 'x86_64', 'op': 'add'},
            {'op': 'add', 'path': '/properties/memory_mb', 'value': '12288'},
            {'path': '/properties/local_gb', 'value': '999', 'op': 'add'}
        ]
        self.patch_root_hints = [
            {'op': 'add', 'path': '/properties/cpus', 'value': '4'},
            {'path': '/properties/cpu_arch', 'value': 'x86_64', 'op': 'add'},
            {'op': 'add', 'path': '/properties/memory_mb', 'value': '12288'},
            {'path': '/properties/local_gb', 'value': '19', 'op': 'add'}
        ]

        self.node.power_state = 'power off'

        self.cfg = self.useFixture(config_fixture.Config())
        conf_file = get_test_conf_file()
        self.cfg.set_config_files([conf_file])

    def tearDown(self):
        super(Base, self).tearDown()
        node_cache._delete_node(self.uuid)

    def call(self, method, endpoint, data=None, expect_error=None,
             api_version=None):
        if data is not None:
            data = json.dumps(data)
        endpoint = self.ROOT_URL + endpoint
        headers = {'X-Auth-Token': 'token'}
        if api_version:
            headers[main._VERSION_HEADER] = '%d.%d' % api_version
        res = getattr(requests, method.lower())(endpoint, data=data,
                                                headers=headers)
        if expect_error:
            self.assertEqual(expect_error, res.status_code)
        else:
            if res.status_code >= 400:
                msg = ('%(meth)s %(url)s failed with code %(code)s: %(msg)s' %
                       {'meth': method.upper(), 'url': endpoint,
                        'code': res.status_code, 'msg': get_error(res)})
                raise AssertionError(msg)
        return res

    def call_introspect(self, uuid, new_ipmi_username=None,
                        new_ipmi_password=None, **kwargs):
        endpoint = '/v1/introspection/%s' % uuid
        if new_ipmi_password:
            endpoint += '?new_ipmi_password=%s' % new_ipmi_password
            if new_ipmi_username:
                endpoint += '&new_ipmi_username=%s' % new_ipmi_username
        return self.call('post', endpoint, **kwargs)

    def call_get_status(self, uuid, **kwargs):
        return self.call('get', '/v1/introspection/%s' % uuid, **kwargs).json()

    @_query_string('marker', 'limit')
    def call_get_statuses(self, query_string='', **kwargs):
        path = '/v1/introspection'
        return self.call('get', path + query_string, **kwargs).json()

    def call_abort_introspect(self, uuid, **kwargs):
        return self.call('post', '/v1/introspection/%s/abort' % uuid, **kwargs)

    def call_reapply(self, uuid, **kwargs):
        return self.call('post', '/v1/introspection/%s/data/unprocessed' %
                         uuid, **kwargs)

    def call_continue(self, data, **kwargs):
        return self.call('post', '/v1/continue', data=data, **kwargs).json()

    def call_add_rule(self, data, **kwargs):
        return self.call('post', '/v1/rules', data=data, **kwargs).json()

    def call_list_rules(self, **kwargs):
        return self.call('get', '/v1/rules', **kwargs).json()['rules']

    def call_delete_rules(self, **kwargs):
        self.call('delete', '/v1/rules', **kwargs)

    def call_delete_rule(self, uuid, **kwargs):
        self.call('delete', '/v1/rules/' + uuid, **kwargs)

    def call_get_rule(self, uuid, **kwargs):
        return self.call('get', '/v1/rules/' + uuid, **kwargs).json()

    def _fake_status(self, finished=mock.ANY, error=mock.ANY,
                     started_at=mock.ANY, finished_at=mock.ANY,
                     links=mock.ANY):
        return {'uuid': self.uuid, 'finished': finished, 'error': error,
                'finished_at': finished_at, 'started_at': started_at,
                'links': [{u'href': u'%s/v1/introspection/%s' % (self.ROOT_URL,
                                                                 self.uuid),
                           u'rel': u'self'}]}

    def check_status(self, status, finished, error=None):
        self.assertEqual(
            self._fake_status(finished=finished,
                              finished_at=finished and mock.ANY or None,
                              error=error),
            status
        )
        curr_time = datetime.datetime.fromtimestamp(
            time.time(), tz=pytz.timezone(time.tzname[0]))
        started_at = timeutils.parse_isotime(status['started_at'])
        self.assertLess(started_at, curr_time)
        if finished:
            finished_at = timeutils.parse_isotime(status['finished_at'])
            self.assertLess(started_at, finished_at)
            self.assertLess(finished_at, curr_time)
        else:
            self.assertIsNone(status['finished_at'])

    def db_row(self):
        """return database row matching self.uuid."""
        return db.model_query(db.Node).get(self.uuid)


class Test(Base):
    def test_bmc(self):
        self.call_introspect(self.uuid)
        eventlet.greenthread.sleep(DEFAULT_SLEEP)
        self.cli.node.set_power_state.assert_called_once_with(self.uuid,
                                                              'reboot')

        status = self.call_get_status(self.uuid)
        self.check_status(status, finished=False)

        res = self.call_continue(self.data)
        self.assertEqual({'uuid': self.uuid}, res)
        eventlet.greenthread.sleep(DEFAULT_SLEEP)

        self.cli.node.update.assert_called_once_with(self.uuid, mock.ANY)
        self.assertCalledWithPatch(self.patch, self.cli.node.update)
        self.cli.port.create.assert_called_once_with(
            node_uuid=self.uuid, address='11:22:33:44:55:66')

        status = self.call_get_status(self.uuid)
        self.check_status(status, finished=True)

    def test_setup_ipmi(self):
        patch_credentials = [
            {'op': 'add', 'path': '/driver_info/ipmi_username',
             'value': 'admin'},
            {'op': 'add', 'path': '/driver_info/ipmi_password',
             'value': 'pwd'},
        ]
        self.node.provision_state = 'enroll'
        self.call_introspect(self.uuid, new_ipmi_username='admin',
                             new_ipmi_password='pwd')
        eventlet.greenthread.sleep(DEFAULT_SLEEP)
        self.assertFalse(self.cli.node.set_power_state.called)

        status = self.call_get_status(self.uuid)
        self.check_status(status, finished=False)

        res = self.call_continue(self.data)
        self.assertEqual('admin', res['ipmi_username'])
        self.assertEqual('pwd', res['ipmi_password'])
        self.assertTrue(res['ipmi_setup_credentials'])
        eventlet.greenthread.sleep(DEFAULT_SLEEP)

        self.assertCalledWithPatch(self.patch + patch_credentials,
                                   self.cli.node.update)
        self.cli.port.create.assert_called_once_with(
            node_uuid=self.uuid, address='11:22:33:44:55:66')

        status = self.call_get_status(self.uuid)
        self.check_status(status, finished=True)

    def test_introspection_statuses(self):
        self.call_introspect(self.uuid)
        eventlet.greenthread.sleep(DEFAULT_SLEEP)

        # NOTE(zhenguo): only test finished=False here, as we don't know
        # other nodes status in this thread.
        statuses = self.call_get_statuses().get('introspection')
        self.assertIn(self._fake_status(finished=False), statuses)

        # check we've got 1 status with a limit of 1
        statuses = self.call_get_statuses(limit=1).get('introspection')
        self.assertEqual(1, len(statuses))

        all_statuses = self.call_get_statuses().get('introspection')
        marker_statuses = self.call_get_statuses(
            marker=self.uuid, limit=1).get('introspection')
        marker_index = all_statuses.index(self.call_get_status(self.uuid))
        # marker is the last row on previous page
        self.assertEqual(all_statuses[marker_index+1:marker_index+2],
                         marker_statuses)

        self.call_continue(self.data)
        eventlet.greenthread.sleep(DEFAULT_SLEEP)

        status = self.call_get_status(self.uuid)
        self.check_status(status, finished=True)

        # fetch all statuses and db nodes to assert pagination
        statuses = self.call_get_statuses().get('introspection')
        nodes = db.model_query(db.Node).order_by(
            db.Node.started_at.desc()).all()

        # assert ordering
        self.assertEqual([node.uuid for node in nodes],
                         [status_.get('uuid') for status_ in statuses])

        # assert pagination
        half = len(nodes) // 2
        marker = nodes[half].uuid
        statuses = self.call_get_statuses(marker=marker).get('introspection')
        self.assertEqual([node.uuid for node in nodes[half + 1:]],
                         [status_.get('uuid') for status_ in statuses])

        # assert status links work
        self.assertEqual([self.call_get_status(status_.get('uuid'))
                          for status_ in statuses],
                         [self.call('GET', urllib.parse.urlparse(
                             status_.get('links')[0].get('href')).path).json()
                          for status_ in statuses])

    def test_rules_api(self):
        res = self.call_list_rules()
        self.assertEqual([], res)

        rule = {'conditions': [],
                'actions': [{'action': 'fail', 'message': 'boom'}],
                'description': 'Cool actions'}
        res = self.call_add_rule(rule)
        self.assertTrue(res['uuid'])
        rule['uuid'] = res['uuid']
        rule['links'] = res['links']
        self.assertEqual(rule, res)

        res = self.call('get', rule['links'][0]['href']).json()
        self.assertEqual(rule, res)

        res = self.call_list_rules()
        self.assertEqual(rule['links'], res[0].pop('links'))
        self.assertEqual([{'uuid': rule['uuid'],
                           'description': 'Cool actions'}],
                         res)

        res = self.call_get_rule(rule['uuid'])
        self.assertEqual(rule, res)

        self.call_delete_rule(rule['uuid'])
        res = self.call_list_rules()
        self.assertEqual([], res)

        links = rule.pop('links')
        del rule['uuid']
        for _ in range(3):
            self.call_add_rule(rule)

        res = self.call_list_rules()
        self.assertEqual(3, len(res))

        self.call_delete_rules()
        res = self.call_list_rules()
        self.assertEqual([], res)

        self.call('get', links[0]['href'], expect_error=404)
        self.call('delete', links[0]['href'], expect_error=404)

    def test_introspection_rules(self):
        self.node.extra['bar'] = 'foo'
        rules = [
            {
                'conditions': [
                    {'field': 'memory_mb', 'op': 'eq', 'value': 12288},
                    {'field': 'local_gb', 'op': 'gt', 'value': 998},
                    {'field': 'local_gb', 'op': 'lt', 'value': 1000},
                    {'field': 'local_gb', 'op': 'matches', 'value': '[0-9]+'},
                    {'field': 'cpu_arch', 'op': 'contains', 'value': '[0-9]+'},
                    {'field': 'root_disk.wwn', 'op': 'is-empty'},
                    {'field': 'inventory.interfaces[*].ipv4_address',
                     'op': 'contains', 'value': r'127\.0\.0\.1',
                     'invert': True, 'multiple': 'all'},
                    {'field': 'i.do.not.exist', 'op': 'is-empty'},
                ],
                'actions': [
                    {'action': 'set-attribute', 'path': '/extra/foo',
                     'value': 'bar'}
                ]
            },
            {
                'conditions': [
                    {'field': 'memory_mb', 'op': 'ge', 'value': 100500},
                ],
                'actions': [
                    {'action': 'set-attribute', 'path': '/extra/bar',
                     'value': 'foo'},
                    {'action': 'fail', 'message': 'boom'}
                ]
            }
        ]
        for rule in rules:
            self.call_add_rule(rule)

        self.call_introspect(self.uuid)
        eventlet.greenthread.sleep(DEFAULT_SLEEP)
        self.call_continue(self.data)
        eventlet.greenthread.sleep(DEFAULT_SLEEP)

        self.cli.node.update.assert_any_call(
            self.uuid,
            [{'op': 'add', 'path': '/extra/foo', 'value': 'bar'}])

    def test_conditions_scheme_actions_path(self):
        rules = [
            {
                'conditions': [
                    {'field': 'node://properties.local_gb', 'op': 'eq',
                     'value': 40},
                    {'field': 'node://driver_info.ipmi_address', 'op': 'eq',
                     'value': self.bmc_address},
                ],
                'actions': [
                    {'action': 'set-attribute', 'path': '/extra/foo',
                     'value': 'bar'}
                ]
            },
            {
                'conditions': [
                    {'field': 'data://inventory.cpu.count', 'op': 'eq',
                     'value': self.data['inventory']['cpu']['count']},
                ],
                'actions': [
                    {'action': 'set-attribute',
                     'path': '/driver_info/ipmi_address',
                     'value': '{data[inventory][bmc_address]}'}
                ]
            }
        ]
        for rule in rules:
            self.call_add_rule(rule)

        self.call_introspect(self.uuid)
        eventlet.greenthread.sleep(DEFAULT_SLEEP)
        self.call_continue(self.data)
        eventlet.greenthread.sleep(DEFAULT_SLEEP)

        self.cli.node.update.assert_any_call(
            self.uuid,
            [{'op': 'add', 'path': '/extra/foo', 'value': 'bar'}])

        self.cli.node.update.assert_any_call(
            self.uuid,
            [{'op': 'add', 'path': '/driver_info/ipmi_address',
              'value': self.data['inventory']['bmc_address']}])

    def test_root_device_hints(self):
        self.node.properties['root_device'] = {'size': 20}

        self.call_introspect(self.uuid)
        eventlet.greenthread.sleep(DEFAULT_SLEEP)
        self.cli.node.set_power_state.assert_called_once_with(self.uuid,
                                                              'reboot')

        status = self.call_get_status(self.uuid)
        self.check_status(status, finished=False)

        res = self.call_continue(self.data)
        self.assertEqual({'uuid': self.uuid}, res)
        eventlet.greenthread.sleep(DEFAULT_SLEEP)

        self.assertCalledWithPatch(self.patch_root_hints, self.cli.node.update)
        self.cli.port.create.assert_called_once_with(
            node_uuid=self.uuid, address='11:22:33:44:55:66')

        status = self.call_get_status(self.uuid)
        self.check_status(status, finished=True)

    def test_abort_introspection(self):
        self.call_introspect(self.uuid)
        eventlet.greenthread.sleep(DEFAULT_SLEEP)
        self.cli.node.set_power_state.assert_called_once_with(self.uuid,
                                                              'reboot')
        status = self.call_get_status(self.uuid)
        self.check_status(status, finished=False)

        res = self.call_abort_introspect(self.uuid)
        eventlet.greenthread.sleep(DEFAULT_SLEEP)

        self.assertEqual(202, res.status_code)
        status = self.call_get_status(self.uuid)
        self.assertTrue(status['finished'])
        self.assertEqual('Canceled by operator', status['error'])

        # Note(mkovacik): we're checking just this doesn't pass OK as
        # there might be either a race condition (hard to test) that
        # yields a 'Node already finished.' or an attribute-based
        # look-up error from some pre-processing hooks because
        # node_info.finished() deletes the look-up attributes only
        # after releasing the node lock
        self.call('post', '/v1/continue', self.data, expect_error=400)

    @mock.patch.object(swift, 'store_introspection_data', autospec=True)
    @mock.patch.object(swift, 'get_introspection_data', autospec=True)
    def test_stored_data_processing(self, get_mock, store_mock):
        cfg.CONF.set_override('store_data', 'swift', 'processing')

        # ramdisk data copy
        # please mind the data is changed during processing
        ramdisk_data = json.dumps(copy.deepcopy(self.data))
        get_mock.return_value = ramdisk_data

        self.call_introspect(self.uuid)
        eventlet.greenthread.sleep(DEFAULT_SLEEP)
        self.cli.node.set_power_state.assert_called_once_with(self.uuid,
                                                              'reboot')

        res = self.call_continue(self.data)
        self.assertEqual({'uuid': self.uuid}, res)
        eventlet.greenthread.sleep(DEFAULT_SLEEP)

        status = self.call_get_status(self.uuid)
        self.check_status(status, finished=True)

        res = self.call_reapply(self.uuid)
        self.assertEqual(202, res.status_code)
        self.assertEqual('', res.text)
        eventlet.greenthread.sleep(DEFAULT_SLEEP)

        # reapply request data
        get_mock.assert_called_once_with(self.uuid,
                                         suffix='UNPROCESSED')

        # store ramdisk data, store processing result data, store
        # reapply processing result data; the ordering isn't
        # guaranteed as store ramdisk data runs in a background
        # thread; hower, last call has to always be reapply processing
        # result data
        store_ramdisk_call = mock.call(mock.ANY, self.uuid,
                                       suffix='UNPROCESSED')
        store_processing_call = mock.call(mock.ANY, self.uuid,
                                          suffix=None)
        self.assertEqual(3, len(store_mock.call_args_list))
        self.assertIn(store_ramdisk_call,
                      store_mock.call_args_list[0:2])
        self.assertIn(store_processing_call,
                      store_mock.call_args_list[0:2])
        self.assertEqual(store_processing_call,
                         store_mock.call_args_list[2])

        # second reapply call
        get_mock.return_value = ramdisk_data
        res = self.call_reapply(self.uuid)
        self.assertEqual(202, res.status_code)
        self.assertEqual('', res.text)
        eventlet.greenthread.sleep(DEFAULT_SLEEP)

        # reapply saves the result
        self.assertEqual(4, len(store_mock.call_args_list))
        self.assertEqual(store_processing_call,
                         store_mock.call_args_list[-1])

    # TODO(milan): remove the test case in favor of other tests once
    # the introspection status endpoint exposes the state information
    @mock.patch.object(swift, 'store_introspection_data', autospec=True)
    @mock.patch.object(swift, 'get_introspection_data', autospec=True)
    def test_state_transitions(self, get_mock, store_mock):
        """Assert state transitions work as expected."""
        cfg.CONF.set_override('store_data', 'swift', 'processing')

        # ramdisk data copy
        # please mind the data is changed during processing
        ramdisk_data = json.dumps(copy.deepcopy(self.data))
        get_mock.return_value = ramdisk_data

        self.call_introspect(self.uuid)
        reboot_call = mock.call(self.uuid, 'reboot')
        self.cli.node.set_power_state.assert_has_calls([reboot_call])

        eventlet.greenthread.sleep(DEFAULT_SLEEP)
        row = self.db_row()
        self.assertEqual(istate.States.waiting, row.state)

        self.call_continue(self.data)
        eventlet.greenthread.sleep(DEFAULT_SLEEP)

        row = self.db_row()
        self.assertEqual(istate.States.finished, row.state)
        self.assertIsNone(row.error)
        version_id = row.version_id

        self.call_reapply(self.uuid)
        eventlet.greenthread.sleep(DEFAULT_SLEEP)
        row = self.db_row()
        self.assertEqual(istate.States.finished, row.state)
        self.assertIsNone(row.error)
        # the finished state was visited from the reapplying state
        self.assertNotEqual(version_id, row.version_id)

        self.call_introspect(self.uuid)
        eventlet.greenthread.sleep(DEFAULT_SLEEP)
        row = self.db_row()
        self.assertEqual(istate.States.waiting, row.state)
        self.call_abort_introspect(self.uuid)
        row = self.db_row()
        self.assertEqual(istate.States.error, row.state)
        self.assertEqual('Canceled by operator', row.error)

    @mock.patch.object(swift, 'store_introspection_data', autospec=True)
    @mock.patch.object(swift, 'get_introspection_data', autospec=True)
    def test_edge_state_transitions(self, get_mock, store_mock):
        """Assert state transitions work as expected in edge conditions."""
        cfg.CONF.set_override('store_data', 'swift', 'processing')

        # ramdisk data copy
        # please mind the data is changed during processing
        ramdisk_data = json.dumps(copy.deepcopy(self.data))
        get_mock.return_value = ramdisk_data

        # multiple introspect calls
        self.call_introspect(self.uuid)
        self.call_introspect(self.uuid)
        eventlet.greenthread.sleep(DEFAULT_SLEEP)
        # TODO(milan): switch to API once the introspection status
        # endpoint exposes the state information
        row = self.db_row()
        self.assertEqual(istate.States.waiting, row.state)

        # an error -start-> starting state transition is possible
        self.call_abort_introspect(self.uuid)
        self.call_introspect(self.uuid)
        eventlet.greenthread.sleep(DEFAULT_SLEEP)
        row = self.db_row()
        self.assertEqual(istate.States.waiting, row.state)

        # double abort works
        self.call_abort_introspect(self.uuid)
        row = self.db_row()
        version_id = row.version_id
        error = row.error
        self.assertEqual(istate.States.error, row.state)
        self.call_abort_introspect(self.uuid)
        row = self.db_row()
        self.assertEqual(istate.States.error, row.state)
        # assert the error didn't change
        self.assertEqual(error, row.error)
        self.assertEqual(version_id, row.version_id)

        # preventing stale data race condition
        # waiting -> processing is a strict state transition
        self.call_introspect(self.uuid)
        eventlet.greenthread.sleep(DEFAULT_SLEEP)
        row = self.db_row()
        row.state = istate.States.processing
        with db.ensure_transaction() as session:
            row.save(session)
        self.call_continue(self.data, expect_error=400)
        row = self.db_row()
        self.assertEqual(istate.States.error, row.state)
        self.assertIn('no defined transition', row.error)

        # multiple reapply calls
        self.call_introspect(self.uuid)
        eventlet.greenthread.sleep(DEFAULT_SLEEP)
        self.call_continue(self.data)
        eventlet.greenthread.sleep(DEFAULT_SLEEP)
        self.call_reapply(self.uuid)
        row = self.db_row()
        version_id = row.version_id
        self.assertEqual(istate.States.finished, row.state)
        self.assertIsNone(row.error)
        self.call_reapply(self.uuid)
        # assert an finished -reapply-> reapplying -> finished state transition
        row = self.db_row()
        self.assertEqual(istate.States.finished, row.state)
        self.assertIsNone(row.error)
        self.assertNotEqual(version_id, row.version_id)

    def test_without_root_disk(self):
        del self.data['root_disk']
        self.inventory['disks'] = []
        self.patch[-1] = {'path': '/properties/local_gb',
                          'value': '0', 'op': 'add'}

        self.call_introspect(self.uuid)
        eventlet.greenthread.sleep(DEFAULT_SLEEP)
        self.cli.node.set_power_state.assert_called_once_with(self.uuid,
                                                              'reboot')

        status = self.call_get_status(self.uuid)
        self.check_status(status, finished=False)

        res = self.call_continue(self.data)
        self.assertEqual({'uuid': self.uuid}, res)
        eventlet.greenthread.sleep(DEFAULT_SLEEP)

        self.cli.node.update.assert_called_once_with(self.uuid, mock.ANY)
        self.assertCalledWithPatch(self.patch, self.cli.node.update)
        self.cli.port.create.assert_called_once_with(
            node_uuid=self.uuid, address='11:22:33:44:55:66')

        status = self.call_get_status(self.uuid)
        self.check_status(status, finished=True)


@contextlib.contextmanager
def mocked_server():
    d = tempfile.mkdtemp()
    try:
        conf_file = get_test_conf_file()
        with mock.patch.object(ir_utils, 'get_client'):
            dbsync.main(args=['--config-file', conf_file, 'upgrade'])

            cfg.CONF.reset()
            cfg.CONF.unregister_opt(dbsync.command_opt)

            eventlet.greenthread.spawn_n(main.main,
                                         args=['--config-file', conf_file])
            eventlet.greenthread.sleep(1)
            # Wait for service to start up to 30 seconds
            for i in range(10):
                try:
                    requests.get('http://127.0.0.1:5050/v1')
                except requests.ConnectionError:
                    if i == 9:
                        raise
                    print('Service did not start yet')
                    eventlet.greenthread.sleep(3)
                else:
                    break
            # start testing
            yield
            # Make sure all processes finished executing
            eventlet.greenthread.sleep(1)
    finally:
        shutil.rmtree(d)


if __name__ == '__main__':
    with mocked_server():
        unittest.main(verbosity=2)
