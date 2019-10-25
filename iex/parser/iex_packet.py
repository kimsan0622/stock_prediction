from struct import unpack
from datetime import datetime, timezone


# • String(s): Fixed-length ASCII byte sequence, left justified and space filled on the right
# • Long(q): 8 bytes, signed integer
# • Price(q): 8 bytes, signed integer containing a fixed-point number with 4 digits to the right of an implied decimal
# point
# • Integer(I): 4 bytes, unsigned integer
# • Byte(B): 1 byte, unsigned integer
# • Timestamp(q): 8 bytes, signed integer containing a counter of nanoseconds since POSIX (Epoch) time UTC
# • Event Time(I): 4 bytes, unsigned integer containing a counter of seconds since POSIX (Epoch) time UTC

class IEX_Packet(object):
    def __init__(self):
        self.header = dict()
        self.messages = list()
    
    def set_tp_header(self, bytearr):
        self.transport_header = bytearr[0:40]
        self.parse_transport_header(self.transport_header)
        
        if self.msg_cnt > 0:
            self._parse_message(bytearr)
        
    def get_messages(self):
        return self.messages
    
    def parse_and_get_messages(self, bytearr):
        self.set_tp_header(bytearr)
        return self.get_messages()
    
    def _parse_message(self, bytearr):
        self.messages = list()
        offset = 40
        for _ in range(self.msg_cnt):
            msg_len = unpack('<H', bytearr[offset:offset+2])[0]
            msg_data = bytearr[offset+2:offset+2+msg_len]
            iex_msg = self._get_message(msg_data)
            if iex_msg is not None:
                self.messages.append(iex_msg)
            offset = offset + 2 + msg_len
    
    def _get_message(self, bytearr):
        if chr(bytearr[0]) == 'S':
            return IEX_SystemEventMsg(bytearr)
        elif chr(bytearr[0]) == 'D':
            return IEX_SecurityDerectoryMsg(bytearr)
        elif chr(bytearr[0]) == 'H':
            return IEX_TradingStatusMsg(bytearr)
        elif chr(bytearr[0]) == 'O':
            return IEX_OperationalHaltStatusMsg(bytearr)
        elif chr(bytearr[0]) == 'P':
            return IEX_ShortSalePriceTestStatusMsg(bytearr)
        elif chr(bytearr[0]) == 'E':
            return IEX_SecurityEventMsg(bytearr)
        elif chr(bytearr[0]) == '8' or chr(bytearr[0]) == '5':
            return IEX_PriceLevelUpdateMsg(bytearr)
        elif chr(bytearr[0]) == 'Q':
            return IEX_QuoteUpdateMsg(bytearr)
        elif chr(bytearr[0]) == 'T':
            return IEX_TradeReportMsg(bytearr)
        elif chr(bytearr[0]) == 'X':
            return IEX_OfficialPriceMsg(bytearr)
        elif chr(bytearr[0]) == 'B':
            return IEX_TradeBreakMsg(bytearr)
        elif chr(bytearr[0]) == 'A':
            return IEX_AuctionInformationMsg(bytearr)
        else:
            return None

    # IEX-TP v1.0
    def parse_transport_header(self, bytearr):
        self.version, self.reserved, self.msg_protocol_ID, self.channel_ID, self.session_ID, self.payload_len, self.msg_cnt, self.stream_offset, self.first_msg_seq_num, self.send_time = unpack('<2B1H2I2H3q', bytearr)
    
    def __str__(self):
        return '\n'.join([str(k)+':'+str(v) for k, v in self.header.items()])


# message_type(byte)
# flags(byte)
# time_stamp(timestamp)
class IEX_Message(object):
    def __init__(self, bytearr):
        # time_stamp is counter of nanoseconds since POSIX (Epoch) time UTC
        self.message_type, self.flags, self.time_stamp = unpack('<2B1q', bytearr[:10])

    def __str__(self):
        return 'Message Type: {0}\nTimestamp: {1}\n'.format(chr(self.message_type), datetime.utcfromtimestamp(self.time_stamp/1e9).strftime('%Y-%m-%d %H:%M:%S')+'.'+str(int(self.time_stamp%1e9)))
    
    def export_json(self):
        iex_msg = dict()
        iex_msg['message_type'] = chr(self.message_type)
        iex_msg['time_stamp'] = self.time_stamp/1e9
        iex_msg['time_stamp_str'] = datetime.utcfromtimestamp(self.time_stamp/1e9).strftime('%Y-%m-%d %H:%M:%S')+'.'+str(int(self.time_stamp%1e9))
        return iex_msg


'''
system event message: Symbol 'S' (0x53)

The System Event Message is used to indicate events that apply to the market or the data feed.
There will be a single message disseminated per channel for each System Event type within a given trading session.

Parameters
    message_type(byte): S
    system_event(byte): system event identifier
    time_stamp(timestamp): time stamp of the system event

System event
    • f): Start of Messages Outside of heartbeat messages on the lower level protocol, the start of day
    message is the first message sent in any trading session.
    • Start of System Hours This message indicates that IEX is open and ready to start accepting orders.
    • Start of Regular Market Hours This message indicates that DAY and GTX orders, as well as market
    orders and pegged orders, are available for execution on IEX.
    • d): End of Regular Market Hours This message indicates that DAY orders, market orders, and pegged
    orders are no longer accepted by IEX.
    • End of System Hours This message indicates that IEX is now closed and will not accept any new
    orders during this trading session. It is still possible to receive messages after the end of day.
    • End of Messages This is always the last message sent in any trading session.
'''
class IEX_SystemEventMsg(IEX_Message):
    def __init__(self, bytearr):
        super(IEX_SystemEventMsg, self).__init__(bytearr)
        self.system_event = self.flags
        self.system_event_str = ''
    
    def __str__(self):
        return super(IEX_SystemEventMsg, self).__str__() + 'Type: {0}\nSystem Event: {1}\n'.format('System Event', self._get_system_event_str())
    
    def _get_system_event_str(self):
        if chr(self.system_event) == 'O':
            return 'Start of Messages'
        elif chr(self.system_event) == 'S':
            return 'Start of System Hours'
        elif chr(self.system_event) == 'R':
            return 'Start of Regular Market Hours'
        elif chr(self.system_event) == 'M':
            return 'End of Regular Market Hours'
        elif chr(self.system_event) == 'E':
            return 'End of System Hours'
        elif chr(self.system_event) == 'C':
            return 'End of Messages'
        else:
            return ''
    
    def export_json(self):
        iex_msg = super(IEX_SystemEventMsg, self).export_json()
        iex_msg['system_event'] = chr(self.system_event)
        iex_msg['system_event_str'] = self._get_system_event_str()
        return iex_msg

'''
security directory message: Symbol 'D' (0x44)

IEX disseminates a full pre-market spin of Security Directory Messages for all IEX-listed securities. After the pre-market
spin, IEX will use the Security Directory Message to relay changes for an individual security.

Parameters
    message_type(byte): D
    flags(byte): flag values
    time_stamp(timestamp): time stamp of the security information
    symbol(string): security identifier
    round_lot_size(integer): number of shares that represent a round lot
    adjusted POC Price(Price): corporate action adjusted previous official closing price
    LULD_tier(byte): Indicates which Limit Up-Limit Down price band calculation parameter is to be used

Flags
T: Test Security Flag (0: Symbol is not a test security, 1: Symbol is a test security)
W: When Issued Flag (0: Symbol is not a when issued security, 1: Symbol is a when issued security)
E: ETP Flag (0: Symbol is not an ETP  (i.e., Exchange Traded Product), 1: Symbol is an ETP)

LULD Tier
    • 0 (0x0): Not applicable
    • 1 (0x1): Tier 1 NMS Stock
    • 2 (0x2): Tier 2 NMS Stock
'''
class IEX_SecurityDerectoryMsg(IEX_Message):
    def __init__(self, bytearr):
        super(IEX_SecurityDerectoryMsg, self).__init__(bytearr)
        self.flags = self.flags

        # parse message
        self.symbol, self.round_lot_size, self.adjusted_POC_price, self.LULD_tier = unpack('<8s1I1q1B', bytearr[10:])
    
    def __str__(self):
        return super(IEX_SecurityDerectoryMsg, self).__str__() + 'Type: {0}\nSymbol: {1}\nRound Lot Size: {2}\nAdjusted POC Price: {3}$\nLULD Tier: {4}\nFlags:{5}\n'.format('Security Detectory Message', str(self.symbol), self.round_lot_size, self.adjusted_POC_price/1e4, self._get_LULD_tier_str(), self._get_flags_str())
    
    def _get_LULD_tier_str(self):
        if self.LULD_tier== 0:
            return 'Not applicable'
        elif self.LULD_tier== 1:
            return 'Tier 1 NMS Stock'
        elif self.LULD_tier== 2:
            return 'Tier 2 NMS Stock'
        else:
            return ''
    
    def _get_flags_str(self):
        T, W, E = self._parse_flags()
        return 'is a test security: {0}, is a when issued security: {1}, is an ETP: {2}'.format(T, W, E)
    
    def _parse_flags(self):
        T = (self.flags & ord('\x80')) == ord('\x80') # Test Security Flag
        W = (self.flags & ord('\x40')) == ord('\x40') # When Issued Flag
        E = (self.flags & ord('\x20')) == ord('\x20') # ETP Flag
        return (T, W, E)
    
    def export_json(self):
        iex_msg = super(IEX_SecurityDerectoryMsg, self).export_json()
        iex_msg['symbol'] = str(self.symbol)

        iex_msg['flags'] = self.flags
        iex_msg['flags_str'] = self._get_flags_str()
        iex_msg['T'], iex_msg['W'], iex_msg['E'] = self._parse_flags()
        iex_msg['round_lot_size'] = self.round_lot_size
        iex_msg['adjusted_POC_price'] = self.adjusted_POC_price/1e4
        iex_msg['LULD_tier'] = self.LULD_tier
        return iex_msg

'''
trading status message: Symbol 'H' (0x48)

The Trading Status Message is used to indicate the current trading status of a security. For IEX-listed securities, IEX
acts as the primary market and has the authority to institute a trading halt or trading pause in a security due to news
dissemination or regulatory reasons. For non-IEX-listed securities, IEX abides by any regulatory trading halts and
trading pauses instituted by the primary or listing market, as applicable.
IEX disseminates a full pre-market spin of Trading Status Messages indicating the trading status of all securities. In the
spin, IEX will send out a Trading Status Message with "T"(Trading) for all securities that are eligible for trading at the
start of the Pre-Market Session. If a security is absent from the dissemination, firms should assume that the security is
being treated as operationally halted in the IEX Trading System.
After the pre-market spin, IEX will use the Trading Status Message to relay changes in trading status for an individual
security. Messages will be sent when a security is:
    • Halted
    • Paused*
    • Released into an Order Acceptance Period*
    • Released for trading
* The paused and released into an Order Acceptance Period status will be disseminated for IEX-listed securities only.
Trading pauses on non-IEX-listed securities will be treated simply as a halt.

Parameters
    message_type(byte): H
    trading_status(byte): trading status identifier
    time_stamp(timestamp): time stamp of the trading status
    symbol(string): security identifier
    reason(string): reason for the trading status change

Trading Status
    • H (0x48): Trading halted across all US equity markets
    • O (0x4f): Trading halt released into an Order Acceptance Period on IEX (IEX-listed securities only)
    • P (0x50): Trading paused and Order Acceptance Period on IEX (IEX-listed securities only)
    • T (0x54): Trading on IEX

Reason
    IEX populates the REason field for IEX-listed securities when the Trading Status is "H" (Trading Halt) or "O" (Order Acceptance Period). For non-IEX-listed securities, the REason field will be set to "NA" (Reason Not Available) when the Trading Status is "H" (Trading Halt). The Reason will be blank when the Trading Status is "P" (Trading Pause and Order Acceptance Period) or "T" (Trading).
        • Trading Halt Reasons
            o T1: Halt News Pending
            o IPO1: IPO Not Yet Trading
            o IPOD: IPO Deferred
            o MCB3: Market-Wide Circuit Breaker Level 3 Breached
            o NA: Reason Not Available
        • Order Acceptance Period Reasons
            o T2: Halt News Dissemination
            o IPO2: IPO Order Acceptance Period
            o IPO3: IPO Pre-Launch Period
            o MCB1: Market-Wide Circuit Breaker Level 1 Breached
            o MCB2: Market-Wide Circuit Breaker Level 2 Breached
'''
class IEX_TradingStatusMsg(IEX_Message):
    def __init__(self, bytearr):
        super(IEX_TradingStatusMsg, self).__init__(bytearr)
        self.trading_status = self.flags

        # parse message
        self.symbol, self.reason = unpack('<8s4s', bytearr[10:])
    
    def __str__(self):
        return super(IEX_TradingStatusMsg, self).__str__() + 'Type: {0}\nSymbol: {1}\nTrading Status: {2} - {3}\n'.format('Trading Status Message', str(self.symbol), chr(self.trading_status), self._get_trading_status_str())
    
    def _get_trading_status_str(self):
        if chr(self.trading_status) == 'H':
            return 'Trading halted across all US equity markets'
        elif chr(self.trading_status) == 'O':
            return 'Trading halt released into an Order Acceptance Period on IEX (IEX-listed securities only)'
        elif chr(self.trading_status) == 'P':
            return 'Trading paused and Order Acceptance Period on IEX (IEX-listed securities only)'
        elif chr(self.trading_status) == 'T':
            return 'Trading on IEX'
        else:
            return ''

    def export_json(self):
        iex_msg = super(IEX_TradingStatusMsg, self).export_json()
        iex_msg['symbol'] = str(self.symbol)

        iex_msg['trading_status'] = chr(self.trading_status)
        iex_msg['trading_status_str'] = self._get_trading_status_str()
        iex_msg['reason'] = str(self.reason)
        return iex_msg

'''
operational halt status message: Symbol 'O' (0x4f)

The Exchange may suspend trading of one or more securities on IEX for operational reasons and indicates such
operational halt using the Operational Halt Status Message.
IEX disseminates a full pre-market spin of Operational Halt Status Messages indicating the operational halt status of all
securities. In the spin, IEX will send out an Operational Halt Message with "N" Not operationally halted on IEX) for all
securities that are eligible for trading at the start of the Pre-Market Session. If a security is absent from the
dissemination, firms should assume that the security is being treated as operationally halted in the IEX Trading System
at the start of the Pre-Market Session.
After the pre-market spin, IEX will use the Operational Halt Status Message to relay changes in operational halt status
for an individual security.

Parameters
    message_type(byte): O
    operational_halt_status(byte): Operational halt status identifier
    time_stamp(timestamp): time stamp of the operational halt status
    symbol(string): security identifier

Operational Halt Status
    • O (0x4f): IEX specific operational trading halt
    • N (0x4e): Not operationally halted on IEX
'''
class IEX_OperationalHaltStatusMsg(IEX_Message):
    def __init__(self, bytearr):
        super(IEX_OperationalHaltStatusMsg, self).__init__(bytearr)
        self.operational_halt_status = self.flags

        # parse message
        self.symbol = unpack('<8s', bytearr[10:])[0]
    
    def __str__(self):
        return super(IEX_OperationalHaltStatusMsg, self).__str__() + 'Type: {0}\nSymbol: {1}\nOperational Halt Status: {2} - {3}\n'.format('Operational Halt Status Message', str(self.symbol), chr(self.operational_halt_status), self._get_operational_halt_status_str())
    
    def _get_operational_halt_status_str(self):
        if chr(self.operational_halt_status) == 'O':
            return 'IEX specific operational trading halt'
        elif chr(self.operational_halt_status) == 'N':
            return 'Not operationally halted on IEX'
        else:
            return ''
    
    def export_json(self):
        iex_msg = super(IEX_OperationalHaltStatusMsg, self).export_json()
        iex_msg['symbol'] = str(self.symbol)

        iex_msg['operational_halt_status'] = chr(self.operational_halt_status)
        iex_msg['operational_halt_status_str'] = self._get_operational_halt_status_str()
        return iex_msg

'''
short sale price test status message: Symbol 'P' (0x50)

In association with Rule 201 of Regulation SHO, the Short Sale Price Test Message is used to indicate when a short sale
price test restriction is in effect for a security.
IEX disseminates a full pre-market spin of Short Sale Price Test Status Messages indicating the Rule 201 status of all
securities. After the pre-market spin, IEX will use the Short Sale Price Test Status Message in the event of an intraday
status change.
The IEX Trading System will process orders based on the latest short sale price test restriction status.

Parameters
    message_type(byte): P
    short_sale_price_test_status(byte): Reg. SHO short sale price test restriction status
    time_stamp(timestamp): Time stamp of the short sale price test status
    symbol(string): security identifier
    detail(byte): Detail of the Reg. SHO short sale price test restriction status

Short Sale Price Test Status
    • 0 (0x0): Short Sale Price Test Not in Effect
    • 1 (0x1): Short Sale Price Test in Effect

Detail
    • [space] (0x20): No price test in place
    • A (0x41): Short sale price test restriction in effect due to an intraday price drop in the security (i.e., Activated)
    • C (0x43): Short sale price test restriction remains in effect from prior day (i.e., Continued)
    • D (0x44): Short sale price test restriction deactivated (i.e., Deactivated)
    • N (0x4e): Detail Not Available
'''
class IEX_ShortSalePriceTestStatusMsg(IEX_Message):
    def __init__(self, bytearr):
        super(IEX_ShortSalePriceTestStatusMsg, self).__init__(bytearr)
        self.short_sale_price_test_status = self.flags

        # parse message
        self.symbol, self.detail = unpack('<8s1B', bytearr[10:])
    
    def __str__(self):
        return super(IEX_ShortSalePriceTestStatusMsg, self).__str__() + 'Type: {0}\nSymbol: {1}\nShort Sale Price Test Status: {2}\n detail: {3} - {4}\n'.format('Short Sale Price Test Status Message', str(self.symbol), self._get_short_sale_price_test_status_str(), chr(self.detail), self._get_detail_str())
    
    def _get_short_sale_price_test_status_str(self):
        if self.short_sale_price_test_status == ord('\x00'):
            return 'Short Sale Price Test Not in Effect'
        elif self.short_sale_price_test_status == ord('\x01'):
            return 'Short Sale Price Test in Effect'
        else:
            return ''
    
    def _get_detail_str(self):
        if chr(self.detail) == ' ':
            return 'No price test in place'
        elif chr(self.detail) == 'A':
            return 'Short sale price test restriction in effect due to an intraday price drop in the security (i.e., Activated)'
        elif chr(self.detail) == 'C':
            return 'Short sale price test restriction remains in effect from prior day (i.e., Continued)'
        elif chr(self.detail) == 'D':
            return 'Short sale price test restriction deactivated (i.e., Deactivated)'
        elif chr(self.detail) == 'N':
            return 'Detail Not Available'
        else:
            return ''
    
    def export_json(self):
        iex_msg = super(IEX_ShortSalePriceTestStatusMsg, self).export_json()
        iex_msg['symbol'] = str(self.symbol)

        iex_msg['short_sale_price_test_status'] = self.short_sale_price_test_status
        iex_msg['short_sale_price_test_status_str'] = self._get_short_sale_price_test_status_str()
        iex_msg['detail'] = chr(self.detail)
        iex_msg['detail_str'] = self._get_detail_str()
        return iex_msg

'''
security event message: Symbol 'E' (0x45)

The Security Event Message is used to indicate events that apply to a security. A Security Event Message will be sent
whenever such event occurs for a security.

Parameters
    message_type(byte): E
    security_event(byte): Security event identifier
    time_stamp(timestamp): Time stamp of the security event
    symbol(string): Security identifier

Security Event
• O (0x4f): Opening Process Complete This message indicates that the Opening Process is complete in this
security and any orders queued during the Pre-Market Session are now available for execution on the IEX Order
Book for the subject security.
• C (0x43): Closing Process Complete For non-IEX-listed securities, this message indicates that IEX has
completed canceling orders from the IEX Order Book for the subject security that are not eligible for the PostMarket Session. For IEX-listed securities, this message indicates that the closing process (e.g., Closing Auction)
has completed for this security and IEX has completed canceling orders from the IEX Order Book for the subject
security that are not eligible for the Post-Market Session.
'''
class IEX_SecurityEventMsg(IEX_Message):
    def __init__(self, bytearr):
        super(IEX_SecurityEventMsg, self).__init__(bytearr)
        self.security_event = self.flags

        # parse message
        self.symbol = unpack('<8s', bytearr[10:])[0]
    
    def __str__(self):
        return super(IEX_SecurityEventMsg, self).__str__() + 'Type: {0}\nSymbol: {1}\nSecurity Event: {2} - {3}\n'.format('Security Event Message', str(self.symbol), chr(self.security_event), self._get_security_event_str())
    
    def _get_security_event_str(self):
        if chr(self.security_event) == 'O':
            return '''Opening Process Complete This message indicates that the Opening Process is complete in this security and any orders queued during the Pre-Market Session are now available for execution on the IEX Order Book for the subject security.'''
        elif chr(self.security_event) == 'C':
            return '''Closing Process Complete For non-IEX-listed securities, this message indicates that IEX has completed canceling orders from the IEX Order Book for the subject security that are not eligible for the PostMarket Session. For IEX-listed securities, this message indicates that the closing process (e.g., Closing Auction) has completed for this security and IEX has completed canceling orders from the IEX Order Book for the subject security that are not eligible for the Post-Market Session.'''
        else:
            return ''
    
    def export_json(self):
        iex_msg = super(IEX_SecurityEventMsg, self).export_json()
        iex_msg['symbol'] = str(self.symbol)

        iex_msg['security_event'] = chr(self.security_event)
        iex_msg['security_event_str'] = self._get_security_event_str()
        return iex_msg

'''
# price level update message: Symbol '8'(0x38)-on Buy side, '5'(0x35)-on Sell side

DEEP broadcasts a real-time Price Level Update Message each time a displayed price level on IEX is updated during the
trading day. When a price level is removed, IEX will disseminate a size of zero (i.e., 0x0) for the level.

parameters
    message_type(byte): '8' (0x38) - Price Level Update on the Buy Side
                        '5' (0x35) - Price Level Update on the Sell Side
    event_flags(byte): Identifies event processing by the System
    time_stamp(timestamp): Time stamp of the price level update
    symbol(string) Security identifier
    size(integer): Aggregate quoted size
    price(price): Price level to add/update in the IEX Order Book

Event Flags
    Event Flags identifies when the IEX Trading System logic completes processing an event (e.g., a taking order). The IEX
    best bid and offer may be accurately calculated by a recipient when the Event Flags is ON (i.e., 0x1). See
    below for additional details regarding consuming Price Level Update Messages and updating the IEX BBO.
        • 0 (0x0): Order Book is processing an event (i.e., Order Book is in transition)
        • 1 (0x1): Event processing complete (i.e., Order Book transition complete)
'''
class IEX_PriceLevelUpdateMsg(IEX_Message):
    def __init__(self, bytearr):
        super(IEX_PriceLevelUpdateMsg, self).__init__(bytearr)
        self.event_falgs = self.flags

        # parse message
        self.symbol, self.size, self.price = unpack('<8s1I1q', bytearr[10:])
    
    def __str__(self):
        return super(IEX_PriceLevelUpdateMsg, self).__str__() + 'Type: {0} - {5}\nSymbol: {1}\nEvent Flags: {2}\nPrice: {3}$\nSize: {4}\n'.format('Price Level Update Message', str(self.symbol), self._get_event_flags_str(), self.price/1e4, self.size, self._get_message_type_str())
    
    def _get_event_flags_str(self):
        if self.event_falgs == ord('\x00'):
            return 'Order Book is processing an event'
        elif self.event_falgs == ord('\x01'):
            return 'Event processing complete'
        else:
            return ''
        
    def _get_message_type_str(self):
        if chr(self.message_type) == '8':
            return 'Price Level Update on the Buy Side'
        elif chr(self.message_type) == '5':
            return 'Price Level Update on the Sell Side'
        else:
            return ''
    
    def export_json(self):
        iex_msg = super(IEX_PriceLevelUpdateMsg, self).export_json()
        iex_msg['symbol'] = str(self.symbol)

        iex_msg['message_type_str'] = self._get_message_type_str()
        iex_msg['event_falgs'] = self.event_falgs
        iex_msg['event_flag_str'] = self._get_event_flags_str()
        iex_msg['size'] = self.size
        iex_msg['price'] = self.price/1e4
        return iex_msg


'''
Quote Update Message: Symbol 'Q' (0x51)

TOPS broadcasts a real-time Quote Update Message each time IEX's best bid or offer quotation is updated during the
trading day. Prior to the start of trading, IEX publishes a "zero quote" (Bid Price, Bid Size, Ask Price, and Ask Size are
zero) for all symbols in the IEX Trading System.

Parameters
    message_type(byte): Q
    flags(byte): flag values
    time_stamp(timestamp): time stamp of the top of book update
    symbol(string): quoted symbol
    bid_size(integer): aggregate quoted best bid size
    bid_price(price): best quoted bid price
    ask_price(price): best quoted ask price
    ask_size(integer): aggregate quoted best ask size

Flags
A (7'th bit - mask: 0x80): Symbol Availability Flag - 0: Symbol is active (available for trading), 1: Symbol is halted, paused, or otherwise not available for trading on IEX
P (6'th bit - mask: 0x40): Market Session Flag - 0: Regular Market Session, 1: Pre/Post-Market Session
'''
class IEX_QuoteUpdateMsg(IEX_Message):
    def __init__(self, bytearr):
        super(IEX_QuoteUpdateMsg, self).__init__(bytearr)
        self.flags = self.flags

        # parse message
        self.symbol, self.bid_size, self.bid_price, self.ask_price, self.ask_size = unpack('<8s1I2q1I', bytearr[10:])
    
    def __str__(self):
        return super(IEX_QuoteUpdateMsg, self).__str__() + 'Type: {0}\nSymbol: {1}\nFlags:\n{6}\nbid\n\tprice: {2}$\n\tsize: {3}\ask\n\tprice: {4}$\n\tsize: {5}\n'.format('Quote Update Message', str(self.symbol), self.bid_price/1e4, self.bid_size, self.ask_price/1e4, self.ask_size, self._get_flags_str())
    
    def _parse_flags(self):
        A = (self.flags & ord('\x80')) == ord('\x80') # Symbol Availability Flag
        P = (self.flags & ord('\x40')) == ord('\x40') # Market Session Flag
        return (A, P)

    def _get_flags_str(self):
        A, P = self._parse_flags()
        return '\tSymbol Availability: {0}\n\tMarket Session: {1}'.format('Symbol is halted, paused, or otherwise not available for trading on IEX' if A else 'Symbol is active (available for trading)', 'Pre/Post-Market Session' if W else 'Regular Market Session')
    
    def export_json(self):
        iex_msg = super(IEX_QuoteUpdateMsg, self).export_json()
        iex_msg['symbol'] = str(self.symbol)

        iex_msg['flags'] = self.flags
        iex_msg['flags_str'] = self._get_flags_str()
        iex_msg['A'], iex_msg['P'] = self._parse_flags()
        iex_msg['bid_size'] = self.bid_size
        iex_msg['bid_price'] = self.bid_price/1e4
        iex_msg['ask_size'] = self.ask_size
        iex_msg['ask_price'] = self.ask_price/1e4
        return iex_msg
    
    
'''
Trade Report Message: Symbol 'T' (0x54)

Trade Report Messages are sent when an order on the IEX Order Book is executed in whole or in part. TOPS sends a
Trade Report Message for every individual fill.

Parameters
    message_type(byte): T
    sale_condition_flags(byte): flag values
    time_stamp(timestamp): time stamp of the trade
    symbol(string): security identifier
    size(integer): trade volume
    price(price): trade price
    trade_id(long): IEX Generated Identifier. Trade ID is also referenced in the Trade Break Message.

Flags
    F (7'th bit - mask: 0x80): Intermarket Sweep Flag - 0: Non-Intermarket Sweep Order, 1: Intermarket Sweep Order
    T (6'th bit - mask: 0x40): Extended Hours Flag - 0: Regular Market Session Trade, 1: Extended Hours Trade (i.e., Form T sale condition)
    I (5'th bit - mask: 0x20): Odd Lot Flag - 0: Round or Mixed Lot Trade, 1: Odd Lot Trade
    8 (4'th bit - mask: 0x10): Trade Throught Exempt Flag - 0: Trade is subject to Rule 611 (Trade Through) of SEC Reg. NMS, 1: Trade is not subject to Rule 611 (Trade Through) of SEC Reg. NMS*
    X (3'th bit - mask: 0x08): Single-price Closs Trade Flag - 0: Execution during continuous trading, 1: Trade resulting from a single-price cross
'''
class IEX_TradeReportMsg(IEX_Message):
    def __init__(self, bytearr):
        super(IEX_TradeReportMsg, self).__init__(bytearr)
        self.sale_condition_flags = self.flags

        # parse message
        self.symbol, self.size, self.price, self.trade_ID = unpack('<8s1I2q', bytearr[10:])
    
    def __str__(self):
        return super(IEX_TradeReportMsg, self).__str__() + 'Type: {0}\nSymbol: {1}\nFlags: {2}\nTrade:\n\tID: {3}\n\tprice: {4}$\n\tsize: {5}\n'.format('Trade Report Message', str(self.symbol), self._get_sale_condition_flags_str(), self.trade_ID, self.price/1e4, self.size)
    
    def _parse_sale_condition_flags(self):
        F = (self.sale_condition_flags & ord('\x80')) == ord('\x80') # Intermarket Sweep Flag
        T = (self.sale_condition_flags & ord('\x40')) == ord('\x40') # Extended Hours Flag
        I = (self.sale_condition_flags & ord('\x40')) == ord('\x40') # Odd Lot Flag
        TTE = (self.sale_condition_flags & ord('\x40')) == ord('\x40') # Trade Throught Exempt Flag
        X = (self.sale_condition_flags & ord('\x40')) == ord('\x40') # Single-price Closs Trade Flag
        return (F, T, I, TTE, X)

    def _get_sale_condition_flags_str(self):
        F, T, I, TTE, X = self._parse_sale_condition_flags()
        return '{0}, {1}, {2}, {3}, {4}'.format('Intermarket Sweep Order' if F else 'Non-Intermarket Sweep Order', 'Extended Hours Trade' if T else 'Regular Market Session Trade', 'Odd Lot Trade' if I else 'Round or Mixed Lot Trade', 'Trade is not subject to Rule 611 (Trade Through) of SEC Reg. NMS*' if TTE else 'Trade is subject to Rule 611 (Trade Through) of SEC Reg. NMS', 'Trade resulting from a single-price cross' if X else 'Execution during continuous trading')
    
    def export_json(self):
        iex_msg = super(IEX_TradeReportMsg, self).export_json()
        iex_msg['symbol'] = str(self.symbol)

        iex_msg['sale_condition_flags'] = self.sale_condition_flags
        iex_msg['sale_condition_flags_str'] = self._get_sale_condition_flags_str()
        iex_msg['F'], iex_msg['T'], iex_msg['I'], iex_msg['8'], iex_msg['X'] = self._parse_sale_condition_flags()
        iex_msg['size'] = self.size
        iex_msg['price'] = self.price/1e4
        iex_msg['trade_ID'] = self.trade_ID
        return iex_msg

'''
official price Message: Symbol 'X' (0x58)

Official Price Messages are sent for each IEX-listed security to indicate the IEX Official Opening Price and IEX Official
Closing Price. The latest IEX Official Opening (Closing) Price sent by IEX overrides previously disseminated IEX Official
Opening (Closing) Price(s).

Parameters
    message_type(byte): X
    price_type(byte): price type identifier
    time_stamp(timestamp): Time stamp of the official price determination
    symbol(string): Security identifier
    official_price(price): Official opening or closing price, as specified

Price Type
    • 'Q' (0x51) - IEX Official Opening Price.
    • 'M' (0x4d) - IEX Official Closing Price.
'''
class IEX_OfficialPriceMsg(IEX_Message):
    def __init__(self, bytearr):
        super(IEX_OfficialPriceMsg, self).__init__(bytearr)
        self.price_type = self.flags

        # parse message
        self.symbol, self.official_price = unpack('<8s1q', bytearr[10:])
    
    def __str__(self):
        return super(IEX_OfficialPriceMsg, self).__str__() + 'Type: {0}\nSymbol: {1}\nPrice Type: {2}\nOfficial_price: {3}$\n'.format('Official Price Message', str(self.symbol), self._get_price_type_str(), self.official_price/1e4)

    def _get_price_type_str(self):
        if chr(self.price_type) == 'Q':
            return 'IEX Official Opening Price'
        elif chr(self.price_type) == 'M':
            return 'IEX Official Closing Price'
        else:
            return ''
    
    def export_json(self):
        iex_msg = super(IEX_OfficialPriceMsg, self).export_json()
        iex_msg['symbol'] = str(self.symbol)

        iex_msg['price_type'] = chr(self.price_type)
        iex_msg['price_type_str'] = self._get_price_type_str()
        iex_msg['official_price'] = self.official_price/1e4
        return iex_msg

'''
trade break Message: Symbol 'B' (0x42)

Trade Break Messages are sent when an execution on IEX is broken on that same trading day. Trade breaks are rare and
only affect applications that rely upon IEX execution based data.

Parameters
    message_type(byte): B
    sale_condition_flags(byte): flag values
    time_stamp(timestamp): Time stamp of the trade break
    symbol(string): Security identifier
    size(Integer) Trade break volume
    price(price): Trade break price
    trade_ID: IEX trade identifier of the trade that was broken. Trade ID refers to the previously sent Trade Report Message.

Flags
    F (7'th bit - mask: 0x80): Intermarket Sweep Flag - 0: Non-Intermarket Sweep Order, 1: Intermarket Sweep Order
    T (6'th bit - mask: 0x40): Extended Hours Flag - 0: Regular Market Session Trade, 1: Extended Hours Trade (i.e., Form T sale condition)
    I (5'th bit - mask: 0x20): Odd Lot Flag - 0: Round or Mixed Lot Trade, 1: Odd Lot Trade
    8 (4'th bit - mask: 0x10): Trade Throught Exempt Flag - 0: Trade is subject to Rule 611 (Trade Through) of SEC Reg. NMS, 1: Trade is not subject to Rule 611 (Trade Through) of SEC Reg. NMS*
    X (3'th bit - mask: 0x08): Single-price Closs Trade Flag - 0: Execution during continuous trading, 1: Trade resulting from a single-price cross
'''
class IEX_TradeBreakMsg(IEX_Message):
    def __init__(self, bytearr):
        super(IEX_TradeBreakMsg, self).__init__(bytearr)
        self.sale_condition_flags = self.flags

        # parse message
        self.symbol, self.size, self.price, self.trade_ID = unpack('<8s1I2q', bytearr[10:])
    
    def __str__(self):
        return super(IEX_TradeBreakMsg, self).__str__() + 'Type: {0}\nSymbol: {1}\nFlags: {2}\nTrade:\n\tID: {3}\n\tprice: {4}$\n\tsize: {5}\n'.format('Trade Break Message', str(self.symbol), self._get_sale_condition_flags_str(), self.trade_ID, self.price/1e4, self.size)

    def _parse_sale_condition_flags(self):
        F = (self.sale_condition_flags & ord('\x80')) == ord('\x80') # Intermarket Sweep Flag
        T = (self.sale_condition_flags & ord('\x40')) == ord('\x40') # Extended Hours Flag
        I = (self.sale_condition_flags & ord('\x40')) == ord('\x40') # Odd Lot Flag
        TTE = (self.sale_condition_flags & ord('\x40')) == ord('\x40') # Trade Throught Exempt Flag
        X = (self.sale_condition_flags & ord('\x40')) == ord('\x40') # Single-price Closs Trade Flag
        return (F, T, I, TTE, X)
    
    def _get_sale_condition_flags_str(self):
        F, T, I, TTE, X = self._parse_sale_condition_flags()
        return '{0}, {1}, {2}, {3}, {4}'.format('Intermarket Sweep Order' if F else 'Non-Intermarket Sweep Order', 'Extended Hours Trade' if T else 'Regular Market Session Trade', 'Odd Lot Trade' if I else 'Round or Mixed Lot Trade', 'Trade is not subject to Rule 611 (Trade Through) of SEC Reg. NMS*' if TTE else 'Trade is subject to Rule 611 (Trade Through) of SEC Reg. NMS', 'Trade resulting from a single-price cross' if X else 'Execution during continuous trading')
    
    def export_json(self):
        iex_msg = super(IEX_TradeBreakMsg, self).export_json()
        iex_msg['symbol'] = str(self.symbol)

        iex_msg['sale_condition_flags'] = self.sale_condition_flags
        iex_msg['sale_condition_flags_str'] = self._get_sale_condition_flags_str()
        iex_msg['F'], iex_msg['T'], iex_msg['I'], iex_msg['8'], iex_msg['X'] = self._parse_sale_condition_flags()
        iex_msg['size'] = self.size
        iex_msg['price'] = self.price/1e4
        iex_msg['trade_ID'] = self.trade_ID
        return iex_msg


'''
auction information Message: Symbol 'A' (0x41)

TOPS broadcasts an Auction Information Message every one second between the Lock-in Time and the auction match
for Opening and Closing Auctions, and during the Display Only Period for IPO, Halt, and Volatility Auctions. Only IEXlisted securities are eligible for IEX Auctions. See the IEX Auction Process Specification for details regarding IEX
Auctions and IEX Auction Information. 

Parameters
    message_type(byte): A
    auction_type(byte): Auction type identifier
    time_stamp(timestamp): Time stamp of the auction information
    symbol(string): Security identifier
    paired_shares(integer): Number of shares paired at the Reference Price using orders on the Auction Book
    reference_price(price): clearing price at or within the Reference Price Range using orders on the Auction Book
    indicative_clearing_price(price): Clearing price using Eligible Auction Orders
    imbalance_shares(integer): number of unpaired shares at the Reference Price using order on the Auction Book
    imbalance_side(byte): Side of the unpaired shares at the Reference Price using orders on the Auction Book
    extension_number(byte): Number of extensions an auction received
    scheduled_auction_time(event time): projected time of the auction match
    auction_book_clearing_price(price): clearing price using orders on the Auction Book
    collar_reference_price(price): Reference priced used for the auction collar, if any
    lower_auction_collar(price): lower threshold price of the auction collar, if any
    upper_auction_collar(price): Upper threshold price of the auction collar, if any

Auction Type
    • O (0x4f): Opening Auction
    • C (0x43): Closing Auction
    • I (0x49): IPO Auction
    • H (0x48): Halt Auction
    • V (0x56): Volatility Auction

'''
class IEX_AuctionInformationMsg(IEX_Message):
    def __init__(self, bytearr):
        super(IEX_AuctionInformationMsg, self).__init__(bytearr)
        self.auction_type = self.flags

        # parse message
        self.symbol, self.paired_shares, self.reference_price, self.indicative_clearing_price, self.imbalance_shares, self.imbalance_side, self.extension_number, self.scheduled_auction_time, self.auction_book_clearing_price, self.collar_reference_price, self.lower_auction_collar, self.upper_auction_collar = unpack('<8s1I2q1I2B1I4q', bytearr[10:])
    
    def __str__(self):
        return super(IEX_AuctionInformationMsg, self).__str__() + 'Type: {0}\nSymbol: {1}\nAuction Type: {2} - {3}\nPaired Shares: {4}\nReference Price: {5}$\nIndicative Clearing Price: {6}$\nImbalance Shares: {7}\nImbalance Side: {8}\nExtension Number: {9}\nScheduled Auction Time: {10}\nAuction Book Clearing Price: {11}$\nCollar Reference Price: {12}$\nLower Auction Collar: {13}$\nUpper Auction Collar: {14}$\n'.format('Auction Information Message', str(self.symbol), chr(self.auction_type), self._get_auction_type_str(), self.paired_shares, self.reference_price/1e4, self.indicative_clearing_price/1e4, self.imbalance_shares, chr(self.imbalance_side), self.extension_number, datetime.utcfromtimestamp(self.scheduled_auction_time).strftime('%Y-%m-%d %H:%M:%S')+'.'+str(int(self.scheduled_auction_time%1e9)), self.auction_book_clearing_price/1e4, self.collar_reference_price/1e4, self.lower_auction_collar/1e4, self.upper_auction_collar/1e4)
    
    def _get_auction_type_str(self):
        if chr(self.auction_type) == 'O':
            return 'Opening Auction'
        elif chr(self.auction_type) == 'C':
            return 'Closing Auction'
        elif chr(self.auction_type) == 'I':
            return 'IPO Auction'
        elif chr(self.auction_type) == 'H':
            return 'Halt Auction'
        elif chr(self.auction_type) == 'V':
            return 'Volatility Auction'
        else:
            return ''
    
    def export_json(self):
        iex_msg = super(IEX_TradeBreakMsg, self).export_json()
        iex_msg['symbol'] = str(self.symbol)

        iex_msg['auction_type'] = chr(self.auction_type)
        iex_msg['auction_type_str'] = self._get_auction_type_str()

        iex_msg['paired_shares'] = self.paired_shares
        iex_msg['reference_price'] = self.reference_price/1e4
        iex_msg['indicative_clearing_price'] = self.indicative_clearing_price/1e4
        iex_msg['imbalance_shares'] = self.imbalance_shares
        iex_msg['imbalance_side'] = chr(self.imbalance_side)
        iex_msg['extension_number'] = self.extension_number
        iex_msg['scheduled_auction_time'] = self.scheduled_auction_time
        iex_msg['scheduled_auction_time_str'] = datetime.utcfromtimestamp(self.scheduled_auction_time).strftime('%Y-%m-%d %H:%M:%S')
        iex_msg['auction_book_clearing_price'] = self.auction_book_clearing_price/1e4
        iex_msg['collar_reference_price'] = self.collar_reference_price/1e4
        iex_msg['lower_auction_collar'] = self.lower_auction_collar/1e4
        iex_msg['upper_acution_collar'] = self.upper_auction_collar/1e4
        return iex_msg


if __name__ == "__main__":
    from scapy.all import *

    #filename = '../data/test/tops/20180127_IEXTP1_TOPS1.6.pcap'
    filename = '../data/test/deep/20180127_IEXTP1_DEEP1.0.pcap'

    obj = IEX_Packet()

    packets = rdpcap(filename)
    print(packets)
    for packet in packets:
        if packet.haslayer('UDP') == True:
            data = packet['Raw'].load
            messages = obj.parse_and_get_messages(data)
            for message in messages:
                print(message)