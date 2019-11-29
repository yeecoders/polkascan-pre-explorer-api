#  Polkascan PRE Harvester
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
#  data.py

import sqlalchemy as sa
from sqlalchemy import text
from sqlalchemy.orm import relationship, column_property
from sqlalchemy.dialects.mysql import LONGTEXT

from app.models.base import BaseModel
from app.utils.ss58 import ss58_encode, ss58_encode_account_index
from app.settings import LOG_TYPE_AUTHORITIESCHANGE, SUBSTRATE_ADDRESS_TYPE
from app.utils import bech32
from app.settings import HRP
class Block(BaseModel):
    __tablename__ = 'data_block'

    serialize_exclude = ['debug_info']

    serialize_type = 'block'
    id = sa.Column(sa.Integer(), unique=True, autoincrement=True, nullable=False)
    bid = sa.Column(sa.Integer(), nullable=False, index=True, primary_key=True)
    parent_id = sa.Column(sa.Integer(), nullable=False)
    hash = sa.Column(sa.String(66), unique=True, index=True, nullable=False)
    parent_hash = sa.Column(sa.String(66), index=True, nullable=False)
    state_root = sa.Column(sa.String(66), nullable=False)
    extrinsics_root = sa.Column(sa.String(66), nullable=False)
    count_extrinsics = sa.Column(sa.Integer(), nullable=False)
    count_extrinsics_unsigned = sa.Column(sa.Integer(), nullable=False)
    count_extrinsics_signed = sa.Column(sa.Integer(), nullable=False)
    count_extrinsics_error = sa.Column(sa.Integer(), nullable=False)
    count_extrinsics_success = sa.Column(sa.Integer(), nullable=False)
    count_extrinsics_signedby_address = sa.Column(sa.Integer(), nullable=False)
    count_extrinsics_signedby_index = sa.Column(sa.Integer(), nullable=False)
    count_events = sa.Column(sa.Integer(), nullable=False)
    count_events_system = sa.Column(sa.Integer(), nullable=False)
    count_events_module = sa.Column(sa.Integer(), nullable=False)
    count_events_extrinsic = sa.Column(sa.Integer(), nullable=False)
    count_events_finalization = sa.Column(sa.Integer(), nullable=False)
    count_accounts = sa.Column(sa.Integer(), nullable=False)
    count_accounts_new = sa.Column(sa.Integer(), nullable=False)
    count_accounts_reaped = sa.Column(sa.Integer(), nullable=False)
    count_sessions_new = sa.Column(sa.Integer(), nullable=False)
    count_contracts_new = sa.Column(sa.Integer(), nullable=False)
    count_log = sa.Column(sa.Integer(), nullable=False)
    range10000 = sa.Column(sa.Integer(), nullable=False)
    range100000 = sa.Column(sa.Integer(), nullable=False)
    range1000000 = sa.Column(sa.Integer(), nullable=False)
    datetime = sa.Column(sa.DateTime(timezone=True))
    year = sa.Column(sa.Integer(), nullable=True)
    month = sa.Column(sa.Integer(), nullable=True)
    week = sa.Column(sa.Integer(), nullable=True)
    day = sa.Column(sa.Integer(), nullable=True)
    hour = sa.Column(sa.Integer(), nullable=True)
    full_month = sa.Column(sa.Integer(), nullable=True)
    full_week = sa.Column(sa.Integer(), nullable=True)
    full_day = sa.Column(sa.Integer(), nullable=True)
    full_hour = sa.Column(sa.Integer(), nullable=True)
    logs = sa.Column(sa.JSON(), default=None, server_default=None)
    spec_version_id = sa.Column(sa.String(64), nullable=False)
    debug_info = sa.Column(sa.JSON(), default=None, server_default=None)
    mpmr = sa.Column(sa.String(66), nullable=False)
    validators = sa.Column(sa.String(66), nullable=False)
    shard_num = sa.Column(sa.Integer(), index=True, primary_key=True)
    reward = sa.Column(sa.String(66), nullable=False)
    fee = sa.Column(sa.Numeric(precision=65, scale=0), nullable=False)



    @classmethod
    def get_head(cls, session):
        with session.begin():
            query = session.query(cls)
            model = query.order_by(cls.id.desc()).first()

        return model

    @classmethod
    def get_missing_block_ids(cls, session):
        return session.execute(text("""
                                            SELECT
                                              z.expected as block_from, z.got-1 as block_to
                                            FROM (
                                             SELECT
                                              @rownum:=@rownum+1 AS expected,
                                              IF(@rownum=id, 0, @rownum:=id) AS got
                                             FROM
                                              (SELECT @rownum:=0) AS a
                                              JOIN data_block
                                              ORDER BY id
                                             ) AS z
                                            WHERE z.got!=0
                                            ORDER BY block_from DESC
                                            """)
                               )


class BlockTotal(BaseModel):
    __tablename__ = 'data_block_total'

    serialize_type = 'block-total'

    id = sa.Column(sa.Integer(), primary_key=True, autoincrement=False)
    session_id = sa.Column(sa.Integer())
    parent_datetime = sa.Column(sa.DateTime())
    blocktime = sa.Column(sa.Integer(), nullable=False)
    total_extrinsics = sa.Column(sa.Numeric(precision=65, scale=0), nullable=False)
    total_extrinsics_success = sa.Column(sa.Numeric(precision=65, scale=0), nullable=False)
    total_extrinsics_error = sa.Column(sa.Numeric(precision=65, scale=0), nullable=False)
    total_extrinsics_signed = sa.Column(sa.Numeric(precision=65, scale=0), nullable=False)
    total_extrinsics_unsigned = sa.Column(sa.Numeric(precision=65, scale=0), nullable=False)
    total_extrinsics_signedby_address = sa.Column(sa.Numeric(precision=65, scale=0), nullable=False)
    total_extrinsics_signedby_index = sa.Column(sa.Numeric(precision=65, scale=0), nullable=False)
    total_events = sa.Column(sa.Numeric(precision=65, scale=0), nullable=False)
    total_events_system = sa.Column(sa.Numeric(precision=65, scale=0), nullable=False)
    total_events_module = sa.Column(sa.Numeric(precision=65, scale=0), nullable=False)
    total_events_extrinsic = sa.Column(sa.Numeric(precision=65, scale=0), nullable=False)
    total_events_finalization = sa.Column(sa.Numeric(precision=65, scale=0), nullable=False)
    total_logs = sa.Column(sa.Numeric(precision=65, scale=0), nullable=False)
    total_blocktime = sa.Column(sa.Numeric(precision=65, scale=0), nullable=False)
    total_accounts = sa.Column(sa.Numeric(precision=65, scale=0), nullable=False)
    total_accounts_new = sa.Column(sa.Numeric(precision=65, scale=0), nullable=False)
    total_accounts_reaped = sa.Column(sa.Numeric(precision=65, scale=0), nullable=False)
    total_sessions_new = sa.Column(sa.Numeric(precision=65, scale=0), nullable=False)
    total_contracts_new = sa.Column(sa.Numeric(precision=65, scale=0), nullable=False)


class Event(BaseModel):
    __tablename__ = 'data_event'
    id = sa.Column(sa.Integer(), unique=True, autoincrement=True, nullable=False)
    block_id = sa.Column(sa.Integer(), primary_key=True, index=True)
    shard_num = sa.Column(sa.Integer(), index=True, primary_key=True)
    block = relationship(Block, foreign_keys=[block_id, shard_num],
                         primaryjoin=block_id == Block.bid and shard_num == Block.shard_num)

    event_idx = sa.Column(sa.Integer(), primary_key=True, index=True)

    extrinsic_idx = sa.Column(sa.Integer(), index=True)

    type = sa.Column(sa.String(4), index=True)

    spec_version_id = sa.Column(sa.Integer())

    module_id = sa.Column(sa.String(64), index=True)
    event_id = sa.Column(sa.String(64), index=True)

    system = sa.Column(sa.SmallInteger(), index=True, nullable=False)
    module = sa.Column(sa.SmallInteger(), index=True, nullable=False)
    phase = sa.Column(sa.SmallInteger())

    attributes = sa.Column(sa.JSON())

    codec_error = sa.Column(sa.Boolean())
    def serialize_id(self):
        return '{}-{}'.format(self.block_id, self.event_idx)

    def serialize_formatting_hook(self, obj_dict):

        for item in obj_dict['attributes']['attributes']:
            if item['type'] in ['AccountId', 'AuthorityId', 'Address'] and item['value']:
                # SS58 format AccountId public keys
                item['orig_value'] = item['value'].replace('0x', '')
                item['value'] = bech32.encode(HRP, bytes().fromhex(item['value'].replace('0x', '')))
           #bech32.encode(HRP, bytes().fromhex(item['value'].replace('0x', '')))

            elif item['type'] in ['AccountIndex'] and item['value']:
                # SS58 format Account index
                item['orig_value'] = item['value']
                item['value'] = bech32.encode(HRP, bytes().fromhex(item['value']))

        return obj_dict


class Extrinsic(BaseModel):
    __tablename__ = 'data_extrinsic'

    id = sa.Column(sa.Integer(), unique=True, autoincrement=True, nullable=False)
    block_id = sa.Column(sa.Integer(), primary_key=True, index=True)
    shard_num = sa.Column(sa.Integer(), index=True, primary_key=True)
    block = relationship(Block, foreign_keys=[block_id, shard_num],
                         primaryjoin=block_id == Block.bid and shard_num == Block.shard_num)
    extrinsic_idx = sa.Column(sa.Integer(), primary_key=True, index=True)
    extrinsic_hash = sa.Column(sa.String(64), index=True, nullable=True)

    extrinsic_length = sa.Column(sa.String(10))
    extrinsic_version = sa.Column(sa.String(2))

    signed = sa.Column(sa.SmallInteger(), index=True, nullable=False)
    unsigned = sa.Column(sa.SmallInteger(), index=True, nullable=False)
    signedby_address = sa.Column(sa.SmallInteger(), nullable=False)
    signedby_index = sa.Column(sa.SmallInteger(), nullable=False)

    address_length = sa.Column(sa.String(2))
    address = sa.Column(sa.String(64), index=True)
    account_index = sa.Column(sa.String(16), index=True)
    account_idx = sa.Column(sa.Integer(), index=True)
    signature = sa.Column(sa.String(128))
    nonce = sa.Column(sa.Integer())

    era = sa.Column(sa.String(4))

    call = sa.Column(sa.String(4))
    module_id = sa.Column(sa.String(64), index=True)
    call_id = sa.Column(sa.String(64), index=True)
    params = sa.Column(sa.JSON())

    success = sa.Column(sa.SmallInteger(), default=0, nullable=False)
    error = sa.Column(sa.SmallInteger(), default=0, nullable=False)

    spec_version_id = sa.Column(sa.Integer())

    codec_error = sa.Column(sa.Boolean(), default=False)
    datetime = sa.Column(sa.DateTime(timezone=True))

    def serialize_id(self):
        return '{}-{}'.format(self.block_id, self.extrinsic_idx)

    def format_address(self, item):
        item['orig_value'] = item['value'].replace('0x', '')
        item['value'] = item['value'] = bech32.encode(HRP, bytes().fromhex(item['value'].replace('0x', '')))
        return item

    def serialize_formatting_hook(self, obj_dict):

        if obj_dict['attributes'].get('address'):
            obj_dict['attributes']['address_id'] = obj_dict['attributes']['address'].replace('0x', '')
            obj_dict['attributes']['address'] = bech32.encode(HRP, bytes().fromhex(obj_dict['attributes']['address'].replace('0x', '')))

        for item in obj_dict['attributes']['params']:
            # SS58 format Addresses public keys
            if item['type'] in ['Address', 'AccountId'] and item['value']:
                self.format_address(item)
            elif item['type'] in ['Vec<Address>', 'Vec<AccountId>', 'Vec<<Lookup as StaticLookup>::Source>'] and item['value']:
                for idx, vec_item in enumerate(item['value']):
                    item['value'][idx] = {
                        'name': idx,
                        'type': 'Address',
                        'value': bech32.encode(HRP, bytes().fromhex(vec_item.replace('0x', ''))),
                        'orig_value': vec_item.replace('0x', '')
                    }
            elif item['type'] == 'Box<Proposal>':
                for proposal_param in item['value'].get('params', []):
                    if proposal_param['type'] == 'Address':
                        self.format_address(proposal_param)

        return obj_dict


class Log(BaseModel):
    __tablename__ = 'data_log'

    id = sa.Column(sa.Integer(), unique=True, autoincrement=True, nullable=False)
    block_id = sa.Column(sa.Integer(), primary_key=True)
    log_idx = sa.Column(sa.Integer(), primary_key=True)
    type_id = sa.Column(sa.Integer(), index=True)
    type = sa.Column(sa.String(64))
    data = sa.Column(sa.JSON())
    shard_num = sa.Column(sa.Integer(), index=True, primary_key=True)

    def serialize_id(self):
        return '{}-{}'.format(self.block_id, self.log_idx)

    def serialize_formatting_hook(self, obj_dict):

        if self.type_id == LOG_TYPE_AUTHORITIESCHANGE:

            for idx, item in enumerate(obj_dict['attributes']['data']['value']):
                obj_dict['attributes']['data']['value'][idx] = bech32.encode(HRP, bytes().fromhex(item.replace('0x', '')))
        return obj_dict


class Account(BaseModel):
    __tablename__ = 'data_account'

    id = sa.Column(sa.String(64), primary_key=True)
    address = sa.Column(sa.String(64), index=True)
    is_reaped = sa.Column(sa.Boolean, default=False)
    is_validator = sa.Column(sa.Boolean, default=False)
    is_nominator = sa.Column(sa.Boolean, default=False)
    is_contract = sa.Column(sa.Boolean, default=False)
    count_reaped = sa.Column(sa.Integer(), default=0)
    balance = sa.Column(sa.Numeric(precision=65, scale=0), nullable=False)
    created_at_block = sa.Column(sa.Integer(), nullable=False)
    updated_at_block = sa.Column(sa.Integer(), nullable=False)
    shard_num = sa.Column(sa.Integer(), index=True, nullable=False)


    def serialize_id(self):
        return self.address


class AccountAudit(BaseModel):
    __tablename__ = 'data_account_audit'

    id = sa.Column(sa.Integer(), primary_key=True, autoincrement=True)
    account_id = sa.Column(sa.String(64), primary_key=True)
    block_id = sa.Column(sa.Integer(), index=True, nullable=False)
    extrinsic_idx = sa.Column(sa.Integer())
    event_idx = sa.Column(sa.Integer())
    type_id = sa.Column(sa.Integer(), nullable=False)
    data = sa.Column(sa.JSON(), default=None, server_default=None, nullable=True)


data_session = sa.Table('data_session', BaseModel.metadata,
    sa.Column('id', sa.Integer(), primary_key=True, autoincrement=False),
    sa.Column('start_at_block', sa.Integer()),
    sa.Column('era', sa.Integer()),
    sa.Column('era_idx', sa.Integer()),
    sa.Column('created_at_block', sa.Integer(), nullable=False),
    sa.Column('created_at_extrinsic', sa.Integer()),
    sa.Column('created_at_event', sa.Integer()),
    sa.Column('count_validators', sa.Integer()),
    sa.Column('count_nominators', sa.Integer())
)


data_session_total = sa.Table('data_session_total', BaseModel.metadata,
    sa.Column('id', sa.Integer(), sa.ForeignKey('data_session.id'), primary_key=True, autoincrement=False),
    sa.Column('end_at_block', sa.Integer()),
    sa.Column('count_blocks', sa.Integer())
)


class Session(BaseModel):
    __table__ = sa.outerjoin(data_session, data_session_total)

    id = column_property(
        data_session.c.id,
        data_session_total.c.id
    )

    start_at_block = data_session.c.start_at_block
    era = data_session.c.era
    era_idx = data_session.c.era_idx
    created_at_block = data_session.c.created_at_block
    created_at_extrinsic = data_session.c.created_at_extrinsic
    created_at_event = data_session.c.created_at_event
    count_validators = data_session.c.count_validators
    count_nominators = data_session.c.count_nominators
    end_at_block = data_session_total.c.end_at_block
    count_blocks = data_session_total.c.count_blocks


class SessionValidator(BaseModel):
    __tablename__ = 'data_session_validator'

    session_id = sa.Column(sa.Integer(), primary_key=True, autoincrement=False)
    rank_validator = sa.Column(sa.Integer(), primary_key=True, autoincrement=False, index=True)
    validator_stash = sa.Column(sa.String(64), index=True)
    validator_controller = sa.Column(sa.String(64), index=True)
    validator_session = sa.Column(sa.String(64), index=True)
    bonded_total = sa.Column(sa.Numeric(precision=65, scale=0), nullable=False)
    bonded_active = sa.Column(sa.Numeric(precision=65, scale=0), nullable=False)
    bonded_nominators = sa.Column(sa.Numeric(precision=65, scale=0), nullable=False)
    bonded_own = sa.Column(sa.Numeric(precision=65, scale=0), nullable=False)
    unlocking = sa.Column(sa.JSON(), default=None, server_default=None, nullable=True)
    count_nominators = sa.Column(sa.Integer(), nullable=True)
    unstake_threshold = sa.Column(sa.Integer(), nullable=True)
    commission = sa.Column(sa.Numeric(precision=65, scale=0), nullable=True)

    def serialize_id(self):
        return '{}-{}'.format(self.session_id, self.rank_validator)

    def serialize_formatting_hook(self, obj_dict):
        obj_dict['attributes']['validator_stash_id'] = self.validator_stash
        if self.validator_stash:
            obj_dict['attributes']['validator_stash'] = bech32.encode(HRP, bytes().fromhex(self.validator_stash.replace('0x', '')))
        else:
            obj_dict['attributes']['validator_stash'] = None

        obj_dict['attributes']['validator_controller_id'] = self.validator_controller

        if self.validator_controller:
            obj_dict['attributes']['validator_controller'] =bech32.encode(HRP, bytes().fromhex(self.validator_controller.replace('0x', '')))
        else:
            obj_dict['attributes']['validator_controller'] = None

        obj_dict['attributes']['validator_session_id'] = self.validator_session
        if self.validator_session:
            obj_dict['attributes']['validator_session'] = bech32.encode(HRP, bytes().fromhex(self.validator_session.replace('0x', '')))
        else:
            obj_dict['attributes']['validator_session'] = None

        return obj_dict


class SessionNominator(BaseModel):
    __tablename__ = 'data_session_nominator'

    session_id = sa.Column(sa.Integer(), primary_key=True, autoincrement=False)
    rank_validator = sa.Column(sa.Integer(), primary_key=True, autoincrement=False, index=True)
    rank_nominator = sa.Column(sa.Integer(), primary_key=True, autoincrement=False, index=True)
    nominator_stash = sa.Column(sa.String(64), index=True)
    nominator_controller = sa.Column(sa.String(64), index=True, nullable=True)
    bonded = sa.Column(sa.Numeric(precision=65, scale=0), nullable=False)

    def serialize_id(self):
        return '{}-{}-{}'.format(self.session_id, self.rank_validator, self.rank_nominator)

    def serialize_formatting_hook(self, obj_dict):
        obj_dict['attributes']['nominator_stash_id'] = self.nominator_stash
        obj_dict['attributes']['nominator_stash'] = bech32.encode(HRP, bytes().fromhex(self.nominator_stash.replace('0x', '')))

        if self.nominator_controller:
            obj_dict['attributes']['nominator_controller_id'] = self.nominator_controller
            obj_dict['attributes']['nominator_controller'] = bech32.encode(HRP, bytes().fromhex(self.nominator_controller.replace('0x', '')))

        return obj_dict


class AccountIndex(BaseModel):
    __tablename__ = 'data_account_index'

    id = sa.Column(sa.Integer(), primary_key=True, autoincrement=False)
    short_address = sa.Column(sa.String(64), index=True)
    account_id = sa.Column(sa.String(64), index=True)
    is_reclaimable = sa.Column(sa.Boolean, default=False)
    is_reclaimed = sa.Column(sa.Boolean, default=False)
    created_at_block = sa.Column(sa.Integer(), nullable=False)
    updated_at_block = sa.Column(sa.Integer(), nullable=False)

    def serialize_id(self):
        return self.short_address

    def serialize_formatting_hook(self, obj_dict):
        obj_dict['attributes']['account_id'] = self.account_id
        if self.account_id:
            obj_dict['attributes']['address'] = bech32.encode(HRP, bytes().fromhex(self.account_id.replace('0x', '')))
        else:
            obj_dict['attributes']['address'] = None

        return obj_dict


class AccountIndexAudit(BaseModel):
    __tablename__ = 'data_account_index_audit'

    id = sa.Column(sa.Integer(), primary_key=True, autoincrement=True)
    account_index_id = sa.Column(sa.Integer(), nullable=True, index=True)
    account_id = sa.Column(sa.String(64), index=True, nullable=False)
    block_id = sa.Column(sa.Integer(), index=True, nullable=False)
    extrinsic_idx = sa.Column(sa.Integer())
    event_idx = sa.Column(sa.Integer())
    type_id = sa.Column(sa.Integer(), nullable=False)
    data = sa.Column(sa.JSON(), default=None, server_default=None, nullable=True)


class DemocracyProposal(BaseModel):
    __tablename__ = 'data_democracy_proposal'

    id = sa.Column(sa.Integer(), primary_key=True, autoincrement=False)
    proposal = sa.Column(sa.JSON(), default=None, server_default=None, nullable=True)
    bond = sa.Column(sa.Numeric(precision=65, scale=0), nullable=False)
    created_at_block = sa.Column(sa.Integer(), nullable=False)
    updated_at_block = sa.Column(sa.Integer(), nullable=False)
    status = sa.Column(sa.String(64))

    def format_address(self, item):
        item['orig_value'] = item['value'].replace('0x', '')
        item['value'] = bech32.encode(HRP, bytes().fromhex(item['value'].replace('0x', '')))
        return item

    def serialize_formatting_hook(self, obj_dict):

        for proposal_param in obj_dict['attributes']['proposal'].get('params', []):
            if proposal_param['type'] == 'Address':
                self.format_address(proposal_param)

        return obj_dict


class DemocracyProposalAudit(BaseModel):
    __tablename__ = 'data_democracy_proposal_audit'

    id = sa.Column(sa.Integer(), primary_key=True, autoincrement=True)
    democracy_proposal_id = sa.Column(sa.Integer(), nullable=False, index=True)
    block_id = sa.Column(sa.Integer(), index=True, nullable=False)
    extrinsic_idx = sa.Column(sa.Integer())
    event_idx = sa.Column(sa.Integer())
    type_id = sa.Column(sa.Integer(), nullable=False)
    data = sa.Column(sa.JSON(), default=None, server_default=None, nullable=True)


class DemocracyReferendum(BaseModel):
    __tablename__ = 'data_democracy_referendum'

    id = sa.Column(sa.Integer(), primary_key=True, autoincrement=False)
    proposal_id = sa.Column(sa.Integer(), nullable=True)
    proposal = sa.Column(sa.JSON(), default=None, server_default=None, nullable=True)
    vote_threshold = sa.Column(sa.String(64))
    success = sa.Column(sa.Boolean(), nullable=True)
    created_at_block = sa.Column(sa.Integer(), nullable=False)
    updated_at_block = sa.Column(sa.Integer(), nullable=False)
    status = sa.Column(sa.String(64))

    def format_address(self, item):
        item['orig_value'] = item['value'].replace('0x', '')
        item['value'] = bech32.encode(HRP, bytes().fromhex(item['value'].replace('0x', '')))
        return item

    def serialize_formatting_hook(self, obj_dict):
        if self.proposal:
            for proposal_param in obj_dict['attributes']['proposal'].get('proposal', {}).get('params', []):
                if proposal_param['type'] == 'Address':
                    self.format_address(proposal_param)

        return obj_dict


class DemocracyReferendumAudit(BaseModel):
    __tablename__ = 'data_democracy_referendum_audit'

    id = sa.Column(sa.Integer(), primary_key=True, autoincrement=True)
    democracy_referendum_id = sa.Column(sa.Integer(), nullable=False, index=True)
    block_id = sa.Column(sa.Integer(), index=True, nullable=False)
    extrinsic_idx = sa.Column(sa.Integer())
    event_idx = sa.Column(sa.Integer())
    type_id = sa.Column(sa.Integer(), nullable=False)
    data = sa.Column(sa.JSON(), default=None, server_default=None, nullable=True)


class DemocracyVote(BaseModel):
    __tablename__ = 'data_democracy_vote'

    id = sa.Column(sa.Integer(), primary_key=True, autoincrement=True)
    democracy_referendum_id = sa.Column(sa.Integer(), nullable=True, index=True)
    vote_account_id = sa.Column(sa.String(64), index=True, nullable=True)
    stash_account_id = sa.Column(sa.String(64), index=True, nullable=True)
    vote_raw = sa.Column(sa.Integer(), nullable=True)
    vote_yes = sa.Column(sa.Boolean(), nullable=True)
    vote_no = sa.Column(sa.Boolean(), nullable=True)
    stash = sa.Column(sa.Numeric(precision=65, scale=0), nullable=True)
    conviction = sa.Column(sa.Integer(), nullable=True)
    vote_yes_weighted = sa.Column(sa.Numeric(precision=65, scale=0), nullable=True)
    vote_no_weighted = sa.Column(sa.Numeric(precision=65, scale=0), nullable=True)
    created_at_block = sa.Column(sa.Integer(), nullable=False)
    updated_at_block = sa.Column(sa.Integer(), nullable=False)

    def serialize_formatting_hook(self, obj_dict):
        obj_dict['attributes']['vote_address'] = bech32.encode(HRP, bytes().fromhex(self.vote_account_id.replace('0x', '')))
        obj_dict['attributes']['stash_address'] = bech32.encode(HRP, bytes().fromhex(self.stash_account_id.replace('0x', '')))
        return obj_dict


class DemocracyVoteAudit(BaseModel):
    __tablename__ = 'data_democracy_vote_audit'

    id = sa.Column(sa.Integer(), primary_key=True, autoincrement=True)
    democracy_referendum_id = sa.Column(sa.Integer(), nullable=False, index=True)
    block_id = sa.Column(sa.Integer(), index=True, nullable=False)
    extrinsic_idx = sa.Column(sa.Integer())
    event_idx = sa.Column(sa.Integer())
    type_id = sa.Column(sa.Integer(), nullable=False)
    data = sa.Column(sa.JSON(), default=None, server_default=None, nullable=True)


class Contract(BaseModel):
    __tablename__ = 'data_contract'

    code_hash = sa.Column(sa.String(64), primary_key=True)
    bytecode = sa.Column(LONGTEXT())
    source = sa.Column(LONGTEXT())
    abi = sa.Column(sa.JSON(), default=None, server_default=None, nullable=True)
    compiler = sa.Column(sa.String(64))
    created_at_block = sa.Column(sa.Integer(), nullable=False)
    created_at_extrinsic = sa.Column(sa.Integer())
    created_at_event = sa.Column(sa.Integer())

    def serialize_id(self):
        return self.code_hash


class Runtime(BaseModel):
    __tablename__ = 'runtime'

    serialize_exclude = ['json_metadata', 'json_metadata_decoded']

    id = sa.Column(sa.Integer(), primary_key=True, autoincrement=False)
    impl_name = sa.Column(sa.String(255))
    impl_version = sa.Column(sa.Integer())
    spec_version = sa.Column(sa.Integer(), nullable=False, unique=True)
    spec_name = sa.Column(sa.String(255))
    authoring_version = sa.Column(sa.Integer())
    apis = sa.Column(sa.JSON(), default=None, server_default=None, nullable=True)
    json_metadata = sa.Column(sa.JSON(), default=None, server_default=None, nullable=True)
    json_metadata_decoded = sa.Column(sa.JSON(), default=None, server_default=None, nullable=True)
    count_modules = sa.Column(sa.Integer(), default=0, nullable=False)
    count_call_functions = sa.Column(sa.Integer(), default=0, nullable=False)
    count_storage_functions = sa.Column(sa.Integer(), default=0, nullable=False)
    count_events = sa.Column(sa.Integer(), default=0, nullable=False)

    def serialize_id(self):
        return self.spec_version


class RuntimeModule(BaseModel):
    __tablename__ = 'runtime_module'
    __table_args__ = (sa.UniqueConstraint('spec_version', 'module_id'),)

    id = sa.Column(sa.Integer(), primary_key=True)
    spec_version = sa.Column(sa.Integer(), nullable=False)
    module_id = sa.Column(sa.String(64), nullable=False)
    prefix = sa.Column(sa.String(255))
    # TODO unused?
    code = sa.Column(sa.String(255))
    name = sa.Column(sa.String(255))
    # TODO unused?
    lookup = sa.Column(sa.String(4), index=True)
    count_call_functions = sa.Column(sa.Integer(), nullable=False)
    count_storage_functions = sa.Column(sa.Integer(), nullable=False)
    count_events = sa.Column(sa.Integer(), nullable=False)

    def serialize_id(self):
        return '{}-{}'.format(self.spec_version, self.module_id)


class RuntimeCall(BaseModel):
    __tablename__ = 'runtime_call'
    __table_args__ = (sa.UniqueConstraint('spec_version', 'module_id', 'call_id'),)

    id = sa.Column(sa.Integer(), primary_key=True)
    spec_version = sa.Column(sa.Integer(), nullable=False)
    module_id = sa.Column(sa.String(64), nullable=False)
    call_id = sa.Column(sa.String(64), nullable=False)
    index = sa.Column(sa.Integer(), nullable=False)
    prefix = sa.Column(sa.String(255))
    code = sa.Column(sa.String(255))
    name = sa.Column(sa.String(255))
    lookup = sa.Column(sa.String(4), index=True)
    documentation = sa.Column(sa.Text())
    count_params = sa.Column(sa.Integer(), nullable=False)

    def serialize_id(self):
        return '{}-{}-{}'.format(self.spec_version, self.module_id, self.call_id)


class RuntimeCallParam(BaseModel):
    __tablename__ = 'runtime_call_param'
    __table_args__ = (sa.UniqueConstraint('runtime_call_id', 'name'),)

    id = sa.Column(sa.Integer(), primary_key=True)
    runtime_call_id = sa.Column(sa.Integer(), nullable=False)
    name = sa.Column(sa.String(255))
    type = sa.Column(sa.String(255))


class RuntimeEvent(BaseModel):
    __tablename__ = 'runtime_event'
    __table_args__ = (sa.UniqueConstraint('spec_version', 'module_id', 'event_id'),)

    id = sa.Column(sa.Integer(), primary_key=True)
    spec_version = sa.Column(sa.Integer(), nullable=False)
    module_id = sa.Column(sa.String(64), nullable=False)
    event_id = sa.Column(sa.String(64), nullable=False)
    index = sa.Column(sa.Integer(), nullable=False)
    prefix = sa.Column(sa.String(255))
    code = sa.Column(sa.String(255))
    name = sa.Column(sa.String(255))
    lookup = sa.Column(sa.String(4), index=True)
    documentation = sa.Column(sa.Text())
    count_attributes = sa.Column(sa.Integer(), nullable=False)

    def serialize_id(self):
        return '{}-{}-{}'.format(self.spec_version, self.module_id, self.event_id)


class RuntimeEventAttribute(BaseModel):
    __tablename__ = 'runtime_event_attribute'
    __table_args__ = (sa.UniqueConstraint('runtime_event_id', 'index'),)

    id = sa.Column(sa.Integer(), primary_key=True)
    runtime_event_id = sa.Column(sa.Integer(), nullable=False)
    index = sa.Column(sa.Integer(), nullable=False)
    type = sa.Column(sa.String(255))


class RuntimeStorage(BaseModel):
    __tablename__ = 'runtime_storage'

    id = sa.Column(sa.Integer(), primary_key=True)
    spec_version = sa.Column(sa.Integer())
    module_id = sa.Column(sa.String(64))
    storage_key = sa.Column(sa.String(32))
    index = sa.Column(sa.Integer())
    name = sa.Column(sa.String(255))
    lookup = sa.Column(sa.String(4), index=True)
    default = sa.Column(sa.String(255))
    modifier = sa.Column(sa.String(64))
    type_hasher = sa.Column(sa.String(255))
    type_key1 = sa.Column(sa.String(255))
    type_key2 = sa.Column(sa.String(255))
    type_value = sa.Column(sa.String(255))
    type_is_linked = sa.Column(sa.SmallInteger())
    type_key2hasher = sa.Column(sa.String(255))
    documentation = sa.Column(sa.Text())

    def serialize_id(self):
        return '{}-{}-{}'.format(self.spec_version, self.module_id, self.name)


class RuntimeConstant(BaseModel):
    __tablename__ = 'runtime_constant'

    id = sa.Column(sa.Integer(), primary_key=True)
    spec_version = sa.Column(sa.Integer())
    module_id = sa.Column(sa.String(64))
    index = sa.Column(sa.Integer())
    name = sa.Column(sa.String(255), index=True)
    type = sa.Column(sa.String(255))
    value = sa.Column(sa.String(255))
    documentation = sa.Column(sa.Text())

    def serialize_id(self):
        return '{}-{}-{}'.format(self.spec_version, self.module_id, self.name)


class RuntimeType(BaseModel):
    __tablename__ = 'runtime_type'
    __table_args__ = (sa.UniqueConstraint('spec_version', 'type_string'),)

    id = sa.Column(sa.Integer(), primary_key=True)
    spec_version = sa.Column(sa.Integer(), nullable=False)
    type_string = sa.Column(sa.String(255))
    decoder_class = sa.Column(sa.String(255), nullable=True)
