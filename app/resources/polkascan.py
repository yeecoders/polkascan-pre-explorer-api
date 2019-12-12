#  Polkascan PRE Explorer API
#
#  Copyright 2018-2019 openAware BV (NL).
#  This file is part of Polkascan.
#
#  Polkascan is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  Polkascan is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with Polkascan. If not, see <http://www.gnu.org/licenses/>.
#
#  polkascan.py
import logging
import falcon
from dogpile.cache.api import NO_VALUE
from sqlalchemy import func
from datetime import datetime
from app.models.data import Block, Extrinsic, Event, RuntimeCall, RuntimeEvent, Runtime, RuntimeModule, \
    RuntimeCallParam, RuntimeEventAttribute, RuntimeType, RuntimeStorage, Account, Session, DemocracyProposal, Contract, \
    BlockTotal, SessionValidator, Log, DemocracyReferendum, AccountIndex, RuntimeConstant, SessionNominator, \
    DemocracyVote
from app.resources.base import JSONAPIResource, JSONAPIListResource, JSONAPIDetailResource
from app.settings import SUBSTRATE_RPC_URL, SUBSTRATE_METADATA_VERSION, SUBSTRATE_ADDRESS_TYPE, TYPE_REGISTRY, HRP
from app.type_registry import load_type_registry
from app.utils.ss58 import ss58_decode, ss58_encode
from scalecodec.base import RuntimeConfiguration
from substrateinterface import SubstrateInterface
from app.utils import bech32
from datetime import datetime, timedelta, timezone
import time


class BlockDetailsResource(JSONAPIDetailResource):

    def get_item_url_name(self):
        return 'block_id'

    def get_item(self, item_id):

        if item_id.isnumeric():
            return Block.query(self.session).filter_by(id=item_id).first()
        elif '-' in item_id:
            st = item_id.split("-")
            return Block.query(self.session).filter_by(bid=int(st[1]), shard_num=int(st[0])).first()

        else:
            return Block.query(self.session).filter_by(hash=item_id).first()

    def get_relationships(self, include_list, item):
        relationships = {}

        if 'extrinsics' in include_list:
            relationships['extrinsics'] = Extrinsic.query(self.session).filter_by(block_id=item.bid,
                                                                                  shard_num=item.shard_num).order_by(
                'extrinsic_idx')
        if 'transactions' in include_list:
            relationships['transactions'] = Extrinsic.query(self.session).filter_by(block_id=item.bid,
                                                                                    signed=1,
                                                                                    shard_num=item.shard_num).order_by(
                'extrinsic_idx')
        if 'inherents' in include_list:
            relationships['inherents'] = Extrinsic.query(self.session).filter_by(block_id=item.bid, signed=0,
                                                                                 shard_num=item.shard_num).order_by(
                'extrinsic_idx')
        if 'events' in include_list:
            relationships['events'] = Event.query(self.session).filter_by(block_id=item.bid, system=0,
                                                                          shard_num=item.shard_num).order_by(
                'event_idx')
        if 'logs' in include_list:
            relationships['logs'] = Log.query(self.session).filter_by(block_id=item.bid,
                                                                      shard_num=item.shard_num).order_by(
                'log_idx')

        return relationships


class BlockListResource(JSONAPIListResource):

    def get_query(self):
        return Block.query(self.session).order_by(
            Block.id.desc()
        )


class BlockTotalDetailsResource(JSONAPIDetailResource):

    def get_item(self, item_id):
        return BlockTotal.query(self.session).get(item_id)


class BlockTotalListResource(JSONAPIListResource):

    def get_query(self):
        return BlockTotal.query(self.session).order_by(
            BlockTotal.id.desc()
        )


class ExtrinsicListResource(JSONAPIListResource):

    def get_query(self):
        return Extrinsic.query(self.session).order_by(
            Extrinsic.block_id.desc()
        )

    def apply_filters(self, query, params):
        print('ExtrinsicListResource apply_filters== {} '.format(params.get('filter[address]')))

        if params.get('filter[signed]'):
            query = query.filter_by(signed=params.get('filter[signed]'))

        if params.get('filter[module_id]'):
            query = query.filter_by(module_id=params.get('filter[module_id]'))

        if params.get('filter[call_id]'):
            query = query.filter_by(call_id=params.get('filter[call_id]'))

        if params.get('filter[address]'):
            account_id = bytes(bech32.decode(HRP, params.get('filter[address]'))[1]).hex()

            query = query.filter_by(address=account_id)

        return query


class ExtrinsicDetailResource(JSONAPIDetailResource):

    def get_item_url_name(self):
        return 'extrinsic_id'

    def get_item(self, item_id):

        if 'origin-' not in item_id and '-' in item_id:
            st = item_id.split("-")
            return Extrinsic.query(self.session).filter_by(extrinsic_idx=int(st[2]), block_id=int(st[1]),
                                                       shard_num=int(st[0])).first()

        if len(item_id) < 10:
            return Extrinsic.query(self.session).filter_by(id=item_id).first()
        if 'origin-' in item_id:
            if '0x' in item_id:
                return Extrinsic.query(self.session).filter_by(origin_hash=item_id[9:]).first()
            else:
                return Extrinsic.query(self.session).filter_by(origin_hash=item_id[7:]).first()

        if item_id[0:2] == '0x':
            return Extrinsic.query(self.session).filter_by(extrinsic_hash=item_id[2:]).first()
        else:
            return Extrinsic.query(self.session).filter_by(extrinsic_hash=item_id).first()




class EventsListResource(JSONAPIListResource):

    def apply_filters(self, query, params):

        if params.get('filter[module_id]'):
            query = query.filter_by(module_id=params.get('filter[module_id]'))

        if params.get('filter[event_id]'):
            query = query.filter_by(event_id=params.get('filter[event_id]'))

        return query

    def get_query(self):
        return Event.query(self.session).order_by(Event.block_id.desc())


class EventDetailResource(JSONAPIDetailResource):

    def get_item_url_name(self):
        return 'event_id'

    def get_item(self, item_id):
        if '-' in item_id:
            st = item_id.split("-")
            return Event.query(self.session).filter_by(event_idx=int(st[2]), block_id=int(st[1]),
                                                     shard_num=int(st[0])).first()

        else:
            return Event.query(self.session).filter_by(id=item_id.split('-')[0]).first()

    # return Event.query(self.session).get(item_id.split('-'))


class LogListResource(JSONAPIListResource):

    def get_query(self):
        return Log.query(self.session).order_by(
            Log.block_id.desc()
        )


class LogDetailResource(JSONAPIDetailResource):

    def get_item(self, item_id):
        if '-' in item_id:
            st = item_id.split("-")
            return Log.query(self.session).filter_by(log_idx=int(st[2]), block_id=int(st[1]),
                                                     shard_num=int(st[0])).first()

        else:
            return Log.query(self.session).filter_by(id=item_id.split('-')[0]).first()

        # return Log.query(self.session).get(item_id.split('-'))


class NetworkStatisticsResource(JSONAPIResource):
    cache_expiration_time = 6

    def on_get(self, req, resp, network_id=None):
        resp.status = falcon.HTTP_200

        # TODO make caching more generic for custom resources

        cache_key = '{}-{}'.format(req.method, req.url)
        console_handler = logging.StreamHandler()
        console_handler.setLevel('INFO')
        logger = logging.getLogger('yee')
        logger.setLevel('DEBUG')
        logger.addHandler(console_handler)
        logger.info(cache_key)

        response = self.cache_region.get(cache_key, self.cache_expiration_time)

        if response is NO_VALUE:

            best_block = Block.query(self.session).filter_by(
                id=self.session.query(func.max(Block.id)).one()[0]).first()
            total_signed_extrinsics = Extrinsic.query(self.session).filter_by(signed=1).count()

            total_accounts = Account.query(self.session).filter_by().count()

            # total_events = Event.query(self.session).count()
            event = Event.query(self.session).filter_by(
                id=self.session.query(func.max(Event.id)).one()[0]).first()
            if best_block:
                substrate = SubstrateInterface(SUBSTRATE_RPC_URL, metadata_version=SUBSTRATE_METADATA_VERSION)

                response = self.get_jsonapi_response(
                    data={
                        'type': 'networkstats',
                        'id': network_id,
                        'attributes': {
                            'best_block': best_block.id,
                            'total_signed_extrinsics': total_signed_extrinsics,
                            'total_events': event.id,
                            'total_events_module': int(best_block.id),
                            'total_blocks': 'N/A',
                            'total_accounts': total_accounts,
                            'total_runtimes': Runtime.query(self.session).count(),
                            'shard_count': int(substrate.get_ShardCount(), 16)
                        }
                    },
                )
            else:
                response = self.get_jsonapi_response(
                    data={
                        'type': 'networkstats',
                        'id': network_id,
                        'attributes': {
                            'best_block': 0,
                            'total_signed_extrinsics': 0,
                            'total_events': 0,
                            'total_events_module': 0,
                            'total_blocks': 'N/A',
                            'total_accounts': 0,
                            'total_runtimes': 0
                        }
                    },
                )
            self.cache_region.set(cache_key, response)
            resp.set_header('X-Cache', 'MISS')
        else:
            resp.set_header('X-Cache', 'HIT')

        resp.media = response


class BalanceTransferListResource(JSONAPIListResource):
    def get_query(self):
        return Extrinsic.query(self.session).filter_by(module_id='balances', call_id='transfer').order_by(
            Extrinsic.block_id.desc())

    def apply_filters(self, query, params):
        if params.get('filter[address]'):
            account_id = bytes(bech32.decode(HRP, params.get('filter[address]'))[1]).hex()

            print('BalanceTransferListResource apply_filters== {} '.format(account_id))

            query = query.filter_by(address=account_id)
        if params.get('filter[call_id]'):
            query = query.filter_by(call_id=params.get('filter[call_id]'))

        if params.get('filter[success]'):
            query = query.filter_by(success=True)

        if params.get('filter[error]'):
            query = query.filter_by(error=True)

        return query

    def serialize_item(self, item):
        if item.address is None:
            sender = ''
        else:
            sender = bech32.encode(HRP, bytes().fromhex(item.address))

        dt = datetime.fromtimestamp(time.mktime(item.datetime.timetuple()), timezone(timedelta(hours=8)))

        return {
            'type': 'balancetransfer',
            'id': item.extrinsic_hash,
            'attributes': {
                'block_id': item.block_id,
                'extrinsic_hash': item.extrinsic_hash,
                'sender': sender,
                'sender_id': item.address,
                'destination': bech32.encode(HRP, bytes().fromhex(item.params[0]['value'])),
                'destination_id': item.params[0]['value'].replace('0x', ''),
                'value': item.params[1]['value'],
                'shard_num': item.shard_num,
                'call_id': item.call_id,
                'success': item.success,
                'error': item.error,
                'datetime': datetime.strftime(dt, '%Y-%m-%d %H:%M:%S')
            }
        }


class BalanceTransferDetailResource(JSONAPIDetailResource):

    def get_item(self, item_id):
        if item_id[0:2] == '0x':
            return Extrinsic.query(self.session).filter_by(extrinsic_hash=item_id[2:]).first()

    def serialize_item(self, item):
        dt = datetime.fromtimestamp(time.mktime(item.datetime.timetuple()), timezone(timedelta(hours=8)))
        print(type(dt), dt)
        return {
            'type': 'balancetransfer',
            'id': item.extrinsic_hash,
            'attributes': {
                'block_id': item.block_id,
                'extrinsic_hash': item.extrinsic_hash,
                'extrinsic_idx': item.extrinsic_idx,
                'sender': bech32.encode(HRP, bytes().fromhex(item.address)),
                'sender_id': item.address,
                'destination': bech32.encode(HRP, bytes().fromhex(item.params[0]['value'])),
                'destination_id': item.params[0]['value'].replace('0x', ''),
                'value': item.params[1]['value'],
                'shard_num': item.shard_num,
                'success': item.success,
                'error': item.error,
                'datetime': datetime.strftime(dt, '%Y-%m-%d %H:%M:%S')
            }
        }


class AccountResource(JSONAPIListResource):

    def get_query(self):
        return Account.query(self.session).order_by(
            Account.updated_at_block.desc()
        )

    def serialize_item(self, item):
        substrate = SubstrateInterface(SUBSTRATE_RPC_URL, metadata_version=SUBSTRATE_METADATA_VERSION)

        return {
            'type': 'account',
            'id': item.address,
            'attributes': {
                'id': item.id,
                'address': item.address,
                'balance': int(substrate.get_Balance(item.address), 16),
                'shard_num': item.shard_num
            }
        }


class AccountDetailResource(JSONAPIDetailResource):
    cache_expiration_time = 6

    def __init__(self):
        RuntimeConfiguration().update_type_registry(load_type_registry('default'))
        if TYPE_REGISTRY != 'default':
            RuntimeConfiguration().update_type_registry(load_type_registry(TYPE_REGISTRY))
        super(AccountDetailResource, self).__init__()

    def get_item(self, item_id):
        account = Account.query(self.session).filter_by(address=item_id).first()
        #  account = Account(
        #      is_reaped=0,
        #      address=item_id,
        #      id=bytes(bech32.decode(HRP, item_id)[1]).hex(),
        #      shard_num=0,
        #      is_validator=1,
        #      is_contract=1,
        #      count_reaped=1,
        #      balance=0,
        #      created_at_block=31,
        #      updated_at_block=31,
        #  )

        return account

    def get_relationships(self, include_list, item):
        relationships = {}

        print('account relationships== {} '.format(item.id))

        if 'recent_extrinsics' in include_list:
            relationships['recent_extrinsics'] = Extrinsic.query(self.session).filter_by(
                address=item.id).order_by(Extrinsic.block_id.desc())[:10]

        if 'indices' in include_list:
            relationships['indices'] = AccountIndex.query(self.session).filter_by(
                account_id=item.id).order_by(AccountIndex.updated_at_block.desc())

        return relationships

    def serialize_item(self, item):
        substrate = SubstrateInterface(SUBSTRATE_RPC_URL, metadata_version=SUBSTRATE_METADATA_VERSION)
        data = item.serialize()
        data['attributes']['free_balance'] = int(
            substrate.get_Balance(item.address), 16)

        data['attributes']['nonce'] = int(
            substrate.get_Nonce(item.address), 16)

        return data


class AccountIndexListResource(JSONAPIListResource):

    def get_query(self):
        return AccountIndex.query(self.session).order_by(
            AccountIndex.updated_at_block.desc()
        )


class AccountIndexDetailResource(JSONAPIDetailResource):

    def get_item(self, item_id):
        return AccountIndex.query(self.session).filter_by(short_address=item_id).first()

    def get_relationships(self, include_list, item):
        relationships = {}

        if 'recent_extrinsics' in include_list:
            relationships['recent_extrinsics'] = Extrinsic.query(self.session).filter_by(
                address=item.account_id).order_by(Extrinsic.block_id.desc())[:10]

        return relationships


class SessionListResource(JSONAPIListResource):
    cache_expiration_time = 60

    def get_query(self):
        return Session.query(self.session).order_by(
            Session.id.desc()
        )


class SessionDetailResource(JSONAPIDetailResource):

    def get_item(self, item_id):
        return Session.query(self.session).get(item_id)

    def get_relationships(self, include_list, item):
        relationships = {}

        if 'blocks' in include_list:
            relationships['blocks'] = Block.query(self.session).filter_by(
                session_id=item.id
            ).order_by(Block.id.desc())

        if 'validators' in include_list:
            relationships['validators'] = SessionValidator.query(self.session).filter_by(
                session_id=item.id
            ).order_by(SessionValidator.rank_validator)

        return relationships


class SessionValidatorListResource(JSONAPIListResource):
    cache_expiration_time = 60

    def get_query(self):
        return SessionValidator.query(self.session).order_by(
            SessionValidator.session_id, SessionValidator.rank_validator
        )

    def apply_filters(self, query, params):
        if params.get('filter[latestSession]'):
            session = Session.query(self.session).order_by(Session.id.desc()).first()

            query = query.filter_by(session_id=session.id)

        return query


class SessionValidatorDetailResource(JSONAPIDetailResource):

    def get_item(self, item_id):
        session_id, rank_validator = item_id.split('-')
        return SessionValidator.query(self.session).filter_by(
            session_id=session_id,
            rank_validator=rank_validator
        ).first()

    def get_relationships(self, include_list, item):
        relationships = {}

        if 'nominators' in include_list:
            relationships['nominators'] = SessionNominator.query(self.session).filter_by(
                session_id=item.session_id, rank_validator=item.rank_validator
            ).order_by(SessionNominator.rank_nominator)

        return relationships


class SessionNominatorListResource(JSONAPIListResource):
    cache_expiration_time = 60

    def get_query(self):
        return SessionNominator.query(self.session).order_by(
            SessionNominator.session_id, SessionNominator.rank_validator, SessionNominator.rank_nominator
        )

    def apply_filters(self, query, params):
        if params.get('filter[latestSession]'):
            session = Session.query(self.session).order_by(Session.id.desc()).first()

            query = query.filter_by(session_id=session.id)

        return query


class DemocracyProposalListResource(JSONAPIListResource):

    def get_query(self):
        return DemocracyProposal.query(self.session).order_by(
            DemocracyProposal.id.desc()
        )


class DemocracyProposalDetailResource(JSONAPIDetailResource):

    def get_item(self, item_id):
        return DemocracyProposal.query(self.session).get(item_id)


class DemocracyReferendumListResource(JSONAPIListResource):

    def get_query(self):
        return DemocracyReferendum.query(self.session).order_by(
            DemocracyReferendum.id.desc()
        )


class DemocracyReferendumDetailResource(JSONAPIDetailResource):

    def get_relationships(self, include_list, item):
        relationships = {}

        if 'votes' in include_list:
            relationships['votes'] = DemocracyVote.query(self.session).filter_by(
                democracy_referendum_id=item.id
            ).order_by(DemocracyVote.updated_at_block.desc())

        return relationships

    def get_item(self, item_id):
        return DemocracyReferendum.query(self.session).get(item_id)


class ContractListResource(JSONAPIListResource):

    def get_query(self):
        return Contract.query(self.session).order_by(
            Contract.created_at_block.desc()
        )


class ContractDetailResource(JSONAPIDetailResource):

    def get_item(self, item_id):
        return Contract.query(self.session).get(item_id)


class RuntimeListResource(JSONAPIListResource):
    cache_expiration_time = 60

    def get_query(self):
        return Runtime.query(self.session).order_by(
            Runtime.id.desc()
        )


class RuntimeDetailResource(JSONAPIDetailResource):

    def get_item(self, item_id):
        return Runtime.query(self.session).get(item_id)

    def get_relationships(self, include_list, item):
        relationships = {}

        if 'modules' in include_list:
            relationships['modules'] = RuntimeModule.query(self.session).filter_by(
                spec_version=item.spec_version
            ).order_by('lookup', 'id')

        if 'types' in include_list:
            relationships['types'] = RuntimeType.query(self.session).filter_by(
                spec_version=item.spec_version
            ).order_by('type_string')

        return relationships


class RuntimeCallListResource(JSONAPIListResource):
    cache_expiration_time = 3600

    def apply_filters(self, query, params):

        if params.get('filter[latestRuntime]'):
            latest_runtime = Runtime.query(self.session).order_by(Runtime.spec_version.desc()).first()

            query = query.filter_by(spec_version=latest_runtime.spec_version)

        if params.get('filter[module_id]'):
            query = query.filter_by(module_id=params.get('filter[module_id]'))

        return query

    def get_query(self):
        return RuntimeCall.query(self.session).order_by(
            RuntimeCall.spec_version.asc(), RuntimeCall.module_id.asc(), RuntimeCall.call_id.asc()
        )


class RuntimeCallDetailResource(JSONAPIDetailResource):

    def get_item_url_name(self):
        return 'runtime_call_id'

    def get_item(self, item_id):
        spec_version, module_id, call_id = item_id.split('-')
        return RuntimeCall.query(self.session).filter_by(
            spec_version=spec_version,
            module_id=module_id,
            call_id=call_id
        ).first()

    def get_relationships(self, include_list, item):
        relationships = {}

        if 'params' in include_list:
            relationships['params'] = RuntimeCallParam.query(self.session).filter_by(
                runtime_call_id=item.id).order_by('id')

        if 'recent_extrinsics' in include_list:
            relationships['recent_extrinsics'] = Extrinsic.query(self.session).filter_by(
                call_id=item.call_id, module_id=item.module_id).order_by(Extrinsic.block_id.desc())[:10]

        return relationships


class RuntimeEventListResource(JSONAPIListResource):
    cache_expiration_time = 3600

    def apply_filters(self, query, params):

        if params.get('filter[latestRuntime]'):
            latest_runtime = Runtime.query(self.session).order_by(Runtime.spec_version.desc()).first()

            query = query.filter_by(spec_version=latest_runtime.spec_version)

        if params.get('filter[module_id]'):
            query = query.filter_by(module_id=params.get('filter[module_id]'))

        return query

    def get_query(self):
        return RuntimeEvent.query(self.session).order_by(
            RuntimeEvent.spec_version.asc(), RuntimeEvent.module_id.asc(), RuntimeEvent.event_id.asc()
        )


class RuntimeEventDetailResource(JSONAPIDetailResource):

    def get_item_url_name(self):
        return 'runtime_event_id'

    def get_item(self, item_id):
        spec_version, module_id, event_id = item_id.split('-')
        return RuntimeEvent.query(self.session).filter_by(
            spec_version=spec_version,
            module_id=module_id,
            event_id=event_id
        ).first()

    def get_relationships(self, include_list, item):
        relationships = {}

        if 'attributes' in include_list:
            relationships['attributes'] = RuntimeEventAttribute.query(self.session).filter_by(
                runtime_event_id=item.id).order_by('id')

        if 'recent_events' in include_list:
            relationships['recent_events'] = Event.query(self.session).filter_by(
                event_id=item.event_id, module_id=item.module_id).order_by(Event.block_id.desc())[:10]

        return relationships


class RuntimeTypeListResource(JSONAPIListResource):
    cache_expiration_time = 3600

    def get_query(self):
        return RuntimeType.query(self.session).order_by(
            'spec_version', 'type_string'
        )

    def apply_filters(self, query, params):
        if params.get('filter[latestRuntime]'):
            latest_runtime = Runtime.query(self.session).order_by(Runtime.spec_version.desc()).first()

            query = query.filter_by(spec_version=latest_runtime.spec_version)

        return query


class RuntimeModuleListResource(JSONAPIListResource):
    cache_expiration_time = 3600

    def get_query(self):
        return RuntimeModule.query(self.session).order_by(
            'spec_version', 'name'
        )

    def apply_filters(self, query, params):
        if params.get('filter[latestRuntime]'):
            latest_runtime = Runtime.query(self.session).order_by(Runtime.spec_version.desc()).first()

            query = query.filter_by(spec_version=latest_runtime.spec_version)

        return query


class RuntimeModuleDetailResource(JSONAPIDetailResource):

    def get_item(self, item_id):
        spec_version, module_id = item_id.split('-')
        return RuntimeModule.query(self.session).filter_by(spec_version=spec_version, module_id=module_id).first()

    def get_relationships(self, include_list, item):
        relationships = {}

        if 'calls' in include_list:
            relationships['calls'] = RuntimeCall.query(self.session).filter_by(
                spec_version=item.spec_version, module_id=item.module_id).order_by(
                'lookup', 'id')

        if 'events' in include_list:
            relationships['events'] = RuntimeEvent.query(self.session).filter_by(
                spec_version=item.spec_version, module_id=item.module_id).order_by(
                'lookup', 'id')

        if 'storage' in include_list:
            relationships['storage'] = RuntimeStorage.query(self.session).filter_by(
                spec_version=item.spec_version, module_id=item.module_id).order_by(
                'name')

        if 'constants' in include_list:
            relationships['constants'] = RuntimeConstant.query(self.session).filter_by(
                spec_version=item.spec_version, module_id=item.module_id).order_by(
                'name')

        return relationships


class RuntimeStorageDetailResource(JSONAPIDetailResource):

    def get_item(self, item_id):
        spec_version, module_id, name = item_id.split('-')
        return RuntimeStorage.query(self.session).filter_by(
            spec_version=spec_version,
            module_id=module_id,
            name=name
        ).first()


class RuntimeConstantListResource(JSONAPIListResource):
    cache_expiration_time = 3600

    def get_query(self):
        return RuntimeConstant.query(self.session).order_by(
            RuntimeConstant.spec_version.desc(), RuntimeConstant.module_id.asc(), RuntimeConstant.name.asc()
        )


class RuntimeConstantDetailResource(JSONAPIDetailResource):

    def get_item(self, item_id):
        spec_version, module_id, name = item_id.split('-')
        return RuntimeConstant.query(self.session).filter_by(
            spec_version=spec_version,
            module_id=module_id,
            name=name
        ).first()
