// ---iex data type definition
// • String(char[]): Fixed-length ASCII byte sequence, left justified and space filled on the right
// • Long(signed long long): 8 bytes, signed integer
// • Price(signed long long): 8 bytes, signed integer containing a fixed-point number with 4 digits to the right of an implied decimal point
// • Integer(unsigned int): 4 bytes, unsigned integer
// • Short(unsigned short): 2 bytes, unsigned integer
// • Byte(unsigned char): 1 byte, unsigned integer
// • Timestamp(signed long long): 8 bytes, signed integer containing a counter of nanoseconds since POSIX (Epoch) time UTC
// • Event Time(unsigned int): 4 bytes, unsigned integer containing a counter of seconds since POSIX (Epoch) time UTC

// ---iex tp header

// version: byte
// reserved: byte
// message protocol id: short
// channel id: integer
// session id: integer
// payload length: short
// message count: short
// stream offset: long
// first message sequence number: long
// send time: timestamp

#include <iostream> // for debugging
#include <string>   // std::string
#include <string.h> // memcpy
#include <vector>   // std::vector
#include <memory>   // std::shared_ptr
#include <tuple>    // std::tuple
#include <sstream>  // std::sstream

#ifdef ENABLE_JSONCPP
#include "json/json.h"
#endif


namespace iex{
    typedef int64_t LONG;
    typedef int64_t PRICE;
    typedef uint32_t INTEGER;
    typedef uint16_t SHORT;
    typedef uint8_t BYTE;
    typedef uint64_t TIME_STAMP;
    typedef uint32_t EVENT_TIME;

    // if we want to add more variable to message class as member except native field of message,
    // we must initialize it using the length of its native message.
    // a length of each messages is defined as below.
    #define IEX_TP_HEADER_SIZE 40
    #define IEX_BASE_MSG_SIZE 10
    #define IEX_D_MSG_SIZE 21
    #define IEX_H_MSG_SIZE 12
    #define IEX_O_MSG_SIZE 8
    #define IEX_P_MSG_SIZE 9
    #define IEX_E_MSG_SIZE 8
    #define IEX_PLU_MSG_SIZE 20
    #define IEX_Q_MSG_SIZE 32
    #define IEX_T_MSG_SIZE 28
    #define IEX_X_MSG_SIZE 16
    #define IEX_B_MSG_SIZE 28
    #define IEX_A_MSG_SIZE 70

    std::string ltrim(std::string str, const std::string& chars = "\t\n\v\f\r ")
    {
        return str.erase(0, str.find_first_not_of(chars));
    }
    
    std::string rtrim(std::string str, const std::string& chars = "\t\n\v\f\r ")
    {
        return str.erase(str.find_last_not_of(chars) + 1);
    }
    
    std::string trim(std::string str, const std::string& chars = "\t\n\v\f\r ")
    {
        return ltrim(rtrim(str, chars), chars);
    }

    // message_type(byte)
    // flags(byte)
    // time_stamp(timestamp)
    class IEX_Message{
    public:
        BYTE _msg_type;
        BYTE _flags;
        TIME_STAMP _time_stamp;
        IEX_Message(const uint8_t * bytes);
        ~IEX_Message();
        virtual void print() = 0;

        #ifdef ENABLE_JSONCPP
        virtual std::string export_json() = 0;
        #endif

        virtual std::string export_str() = 0;
    };

    IEX_Message::IEX_Message(const uint8_t * bytes){
        // parsing
        //memcpy((void *)this->_symbol, bytes, IEX_BASE_MSG_SIZE);
        memcpy((void *)&(this->_msg_type), bytes, 1);
        memcpy((void *)&(this->_flags), bytes + 1, 1);
        memcpy((void *)&(this->_time_stamp), bytes + 2, 8);
    }

    IEX_Message::~IEX_Message(){
        // delete memory
    }

    /*
    system event message: Symbol "S" (0x53)

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
    */
    class IEX_SystemEventMsg:public IEX_Message{
    public:
        IEX_SystemEventMsg(const uint8_t * bytes);
        ~IEX_SystemEventMsg();
        void print() override;

        #ifdef ENABLE_JSONCPP
        std::string export_json() override;
        #endif

        std::string export_str() override;
    };

    IEX_SystemEventMsg::IEX_SystemEventMsg(const uint8_t * bytes):IEX_Message(bytes){
        // do something
    }

    IEX_SystemEventMsg::~IEX_SystemEventMsg(){
        // delete memory
    }

    void IEX_SystemEventMsg::print(){
        time_t tp = this->_time_stamp/1e9;
        printf("message type: %c\ntime_stamp: %ssystem event: %c\n", this->_msg_type, std::asctime(std::gmtime(&tp)), this->_flags);
    }

    #ifdef ENABLE_JSONCPP
    std::string IEX_SystemEventMsg::export_json(){
        Json::Value iex_msg;
        iex_msg["message_type"] = (const char)this->_msg_type;
        iex_msg["time_stamp"] = (double)(this->_time_stamp/1e9);
        iex_msg["system_event"] = (const char)this->_flags;

        Json::StyledWriter writer;
        std::string json_str = writer.write(iex_msg);
        return json_str;
    }
    #endif

    std::string IEX_SystemEventMsg::export_str(){
        std::stringstream sstream;
        sstream << "message_type" << " " << "char" << " " << (char)this->_msg_type <<std::endl;
        sstream << "time_stamp" << " " << "double" << " " << std::to_string((double)(this->_time_stamp/1e9)) << "\n";
        sstream << "system_event" << " " << "char" << " " << (const char)this->_flags << "\n";
        return sstream.str();
    }

    /*
    security directory message: Symbol "D" (0x44)

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
    */
   class IEX_SecurityDerectoryMsg:public IEX_Message{
    public:
        char _symbol[8];
        INTEGER _round_lot_size;
        PRICE _adjusted_POC_price;
        BYTE _LULD_tier;
        IEX_SecurityDerectoryMsg(const uint8_t * bytes);
        ~IEX_SecurityDerectoryMsg();
        void print() override;
        std::tuple<bool, bool, bool> _parse_flags();

        #ifdef ENABLE_JSONCPP
        std::string export_json() override;
        #endif

        std::string export_str() override;
    };

    IEX_SecurityDerectoryMsg::IEX_SecurityDerectoryMsg(const uint8_t * bytes):IEX_Message(bytes){
        // init parameters
        // memcpy((void *)this->_symbol, bytes + IEX_BASE_MSG_SIZE, IEX_D_MSG_SIZE);
        memcpy((void *)this->_symbol, bytes + IEX_BASE_MSG_SIZE, 8);
        memcpy((void *)&(this->_round_lot_size), bytes + IEX_BASE_MSG_SIZE + 8, 4);
        memcpy((void *)&(this->_adjusted_POC_price), bytes + IEX_BASE_MSG_SIZE + 12, 8);
        memcpy((void *)&(this->_LULD_tier), bytes + IEX_BASE_MSG_SIZE+ 20, 1);
    }

    IEX_SecurityDerectoryMsg::~IEX_SecurityDerectoryMsg(){
        // delete memory
    }

    void IEX_SecurityDerectoryMsg::print(){
        time_t tp = this->_time_stamp/1e9;
        printf("message type: %c\ntime_stamp: %ssymbol: %s\nround lot size: %u\nadjusted POC price: %f\nLULD tier: %u\n", this->_msg_type, std::asctime(std::gmtime(&tp)), rtrim(std::string(this->_symbol, 8)).c_str(), this->_round_lot_size, (double)(this->_adjusted_POC_price/1e4), this->_LULD_tier);
    }

    std::tuple<bool, bool, bool> IEX_SecurityDerectoryMsg::_parse_flags(){
        //return std::tuple<bool, bool, bool> flags(this->_flags&0x80, this->_flags&0x40, this->_flags&0x20);
        return std::make_tuple (this->_flags&0x80, this->_flags&0x40, this->_flags&0x20);
    }

    #ifdef ENABLE_JSONCPP
    std::string  IEX_SecurityDerectoryMsg::export_json(){
        Json::Value iex_msg;
        iex_msg["message_type"] = (char)this->_msg_type;
        iex_msg["time_stamp"] = (double)(this->_time_stamp/1e9);
        iex_msg["symbol"] = rtrim(std::string(this->_symbol, 8));
        iex_msg["flags"] = this->_flags;
        bool t, w, e;
        std::tie(t, w, e) = this->_parse_flags();
        iex_msg["T"] = t; iex_msg["W"] = w; iex_msg["E"] = e;
        //std::tie(iex_msg["T"], iex_msg["W"], iex_msg["E"]) = this->_parse_flags();
        iex_msg["round_lot_size"] = this->_round_lot_size;
        iex_msg["adjusted_POC_price"] = (double)this->_adjusted_POC_price/1e4;
        iex_msg["LULD_tier"] = this->_LULD_tier;

        Json::StyledWriter writer;
        std::string json_str = writer.write(iex_msg);
        return json_str;
    }
    #endif

    std::string IEX_SecurityDerectoryMsg::export_str(){
        std::stringstream sstream;
        sstream << "message_type" << " " << "char" << " " << (char)this->_msg_type <<std::endl;
        sstream << "time_stamp" << " " << "double" << " " << std::to_string((double)(this->_time_stamp/1e9)) << "\n";
        sstream << "symbol" << " " << "string" << " " << rtrim(std::string(this->_symbol, 8)) << "\n";
        sstream << "flags" << " " << "uint8_t" << " " << std::to_string(this->_flags) << "\n";
        bool t, w, e;
        std::tie(t, w, e) = this->_parse_flags();
        sstream << "T" << " " << "bool" << " " << std::to_string(t) << "\n";
        sstream << "W" << " " << "bool" << " " << std::to_string(w) << "\n";
        sstream << "E" << " " << "bool" << " " << std::to_string(e) << "\n";
        sstream << "round_lot_size" << " " << "uint32_t" << " " << std::to_string(this->_round_lot_size) << "\n";
        sstream << "adjusted_POC_price" << " " << "int64_t" << " " << std::to_string(this->_adjusted_POC_price) << "\n";
        sstream << "LULD_tier" << " " << "uint8_t" << " " << std::to_string(this->_LULD_tier) << "\n";
        return sstream.str();
    }

    /*
    trading status message: Symbol "H" (0x48)

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
    */
   class IEX_TradingStatusMsg:public IEX_Message{
    public:
        char _symbol[8];
        char _reason[4];
        IEX_TradingStatusMsg(const uint8_t * bytes);
        ~IEX_TradingStatusMsg();
        void print() override;

        #ifdef ENABLE_JSONCPP
        std::string export_json() override;
        #endif

        std::string export_str() override;
    };

    IEX_TradingStatusMsg::IEX_TradingStatusMsg(const uint8_t * bytes):IEX_Message(bytes){
        // init parameters
        //memcpy((void *)this->_symbol, bytes + IEX_BASE_MSG_SIZE, IEX_H_MSG_SIZE);
        memcpy((void *)this->_symbol, bytes + IEX_BASE_MSG_SIZE, 8);
        memcpy((void *)this->_reason, bytes + IEX_BASE_MSG_SIZE + 8, 4);
    }

    IEX_TradingStatusMsg::~IEX_TradingStatusMsg(){
        // delete memory
    }

    void IEX_TradingStatusMsg::print(){
        time_t tp = this->_time_stamp/1e9;
        printf("message type: %c\ntime_stamp: %ssymbol: %s\nreason: %s\n", this->_msg_type, std::asctime(std::gmtime(&tp)), rtrim(std::string(this->_symbol, 8)).c_str(), rtrim(std::string(this->_reason, 4)).c_str());
    }

    #ifdef ENABLE_JSONCPP
    std::string  IEX_TradingStatusMsg::export_json(){
        Json::Value iex_msg;
        iex_msg["message_type"] = (char)this->_msg_type;
        iex_msg["time_stamp"] = (double)(this->_time_stamp/1e9);
        iex_msg["symbol"] = rtrim(std::string(this->_symbol, 8));
        iex_msg["trading_status"] = (char)this->_flags;
        iex_msg["reason"] = rtrim(std::string(this->_reason, 4));

        Json::StyledWriter writer;
        std::string json_str = writer.write(iex_msg);
        return json_str;
    }
    #endif

    std::string IEX_TradingStatusMsg::export_str(){
        std::stringstream sstream;
        sstream << "message_type" << " " << "char" << " " << (char)this->_msg_type <<std::endl;
        sstream << "time_stamp" << " " << "double" << " " << std::to_string((double)(this->_time_stamp/1e9)) << "\n";
        sstream << "symbol" << " " << "string" << " " << rtrim(std::string(this->_symbol, 8)) << "\n";
        sstream << "trading_status" << " " << "char" << " " << (const char)this->_msg_type << "\n";
        sstream << "reason" << " " << "string" << " " << rtrim(std::string(this->_reason, 4)) << "\n";
        return sstream.str();
    }

    /*
    operational halt status message: Symbol "O" (0x4f)

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
    */
   class IEX_OperationalHaltStatusMsg:public IEX_Message{
    public:
        char _symbol[8];
        IEX_OperationalHaltStatusMsg(const uint8_t * bytes);
        ~IEX_OperationalHaltStatusMsg();
        void print() override;

        #ifdef ENABLE_JSONCPP
        std::string export_json() override;
        #endif

        std::string export_str() override;
    };

    IEX_OperationalHaltStatusMsg::IEX_OperationalHaltStatusMsg(const uint8_t * bytes):IEX_Message(bytes){
        // init parameters
        //memcpy((void *)this->_symbol, bytes + IEX_BASE_MSG_SIZE, IEX_O_MSG_SIZE);
        memcpy((void *)this->_symbol, bytes + IEX_BASE_MSG_SIZE, 8);
    }

    IEX_OperationalHaltStatusMsg::~IEX_OperationalHaltStatusMsg(){
        // delete memory
    }

    void IEX_OperationalHaltStatusMsg::print(){
        time_t tp = this->_time_stamp/1e9;
        printf("message type: %c\ntime_stamp: %ssymbol: %s\n", this->_msg_type, std::asctime(std::gmtime(&tp)), rtrim(std::string(this->_symbol, 8)).c_str());
    }

    #ifdef ENABLE_JSONCPP
    std::string  IEX_OperationalHaltStatusMsg::export_json(){
        Json::Value iex_msg;
        iex_msg["message_type"] = (char)this->_msg_type;
        iex_msg["time_stamp"] = (double)(this->_time_stamp/1e9);
        iex_msg["symbol"] = rtrim(std::string(this->_symbol, 8));
        iex_msg["operational_halt_status"] = (char)this->_flags;

        Json::StyledWriter writer;
        std::string json_str = writer.write(iex_msg);
        return json_str;
    }
    #endif

    std::string IEX_OperationalHaltStatusMsg::export_str(){
        std::stringstream sstream;
        sstream << "message_type" << " " << "char" << " " << (char)this->_msg_type <<std::endl;
        sstream << "time_stamp" << " " << "double" << " " << std::to_string((double)(this->_time_stamp/1e9)) << "\n";
        sstream << "symbol" << " " << "string" << " " << rtrim(std::string(this->_symbol, 8)) << "\n";
        sstream << "operational_halt_status" << " " << "char" << " " << (const char)this->_msg_type << "\n";
        return sstream.str();
    }

    /*
    short sale price test status message: Symbol "P" (0x50)

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
    */

   class IEX_ShortSalePriceTestStatusMsg:public IEX_Message{
    public:
        char _symbol[8];
        BYTE _detail;
        IEX_ShortSalePriceTestStatusMsg(const uint8_t * bytes);
        ~IEX_ShortSalePriceTestStatusMsg();
        void print() override;

        #ifdef ENABLE_JSONCPP
        std::string export_json() override;
        #endif

        std::string export_str() override;
    };

    IEX_ShortSalePriceTestStatusMsg::IEX_ShortSalePriceTestStatusMsg(const uint8_t * bytes):IEX_Message(bytes){
        // init parameters
        //memcpy((void *)this->_symbol, bytes + IEX_BASE_MSG_SIZE, IEX_P_MSG_SIZE);
        memcpy((void *)this->_symbol, bytes + IEX_BASE_MSG_SIZE, 8);
        memcpy((void *)&(this->_detail), bytes + IEX_BASE_MSG_SIZE + 8, 1);
    }

    IEX_ShortSalePriceTestStatusMsg::~IEX_ShortSalePriceTestStatusMsg(){
        // delete memory
    }

    void IEX_ShortSalePriceTestStatusMsg::print(){
        time_t tp = this->_time_stamp/1e9;
        printf("message type: %c\ntime_stamp: %ssymbol: %s\ndetail: %u\n", this->_msg_type, std::asctime(std::gmtime(&tp)), rtrim(std::string(this->_symbol, 8)).c_str(), this->_detail);
    }

    #ifdef ENABLE_JSONCPP
    std::string  IEX_ShortSalePriceTestStatusMsg::export_json(){
        Json::Value iex_msg;
        iex_msg["message_type"] = (char)this->_msg_type;
        iex_msg["time_stamp"] = (double)(this->_time_stamp/1e9);
        iex_msg["symbol"] = rtrim(std::string(this->_symbol, 8));
        iex_msg["short_sale_price_test_status"] = this->_flags;
        iex_msg["detail"] = (char)this->_detail;

        Json::StyledWriter writer;
        std::string json_str = writer.write(iex_msg);
        return json_str;
    }
    #endif

    std::string IEX_ShortSalePriceTestStatusMsg::export_str(){
        std::stringstream sstream;
        sstream << "message_type" << " " << "char" << " " << (char)this->_msg_type <<std::endl;
        sstream << "time_stamp" << " " << "double" << " " << std::to_string((double)(this->_time_stamp/1e9)) << "\n";
        sstream << "symbol" << " " << "string" << " " << rtrim(std::string(this->_symbol, 8)) << "\n";
        sstream << "short_sale_price_test_status" << " " << "uint8_t" << " " << std::to_string(this->_flags) << "\n";
        sstream << "detail" << " " << "char" << " " << (char)this->_detail << "\n";
        return sstream.str();
    }

    /*
    security event message: Symbol "E" (0x45)

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
    */
   class IEX_SecurityEventMsg:public IEX_Message{
    public:
        char _symbol[8];
        IEX_SecurityEventMsg(const uint8_t * bytes);
        ~IEX_SecurityEventMsg();
        void print() override;

        #ifdef ENABLE_JSONCPP
        std::string export_json() override;
        #endif

        std::string export_str() override;
    };

    IEX_SecurityEventMsg::IEX_SecurityEventMsg(const uint8_t * bytes):IEX_Message(bytes){
        // init parameters
        //memcpy((void *)this->_symbol, bytes + IEX_BASE_MSG_SIZE, IEX_E_MSG_SIZE);
        memcpy((void *)this->_symbol, bytes + IEX_BASE_MSG_SIZE, 8);
    }

    IEX_SecurityEventMsg::~IEX_SecurityEventMsg(){
        // delete memory
    }

    void IEX_SecurityEventMsg::print(){
        time_t tp = this->_time_stamp/1e9;
        printf("message type: %c\ntime_stamp: %ssymbol: %s\n", this->_msg_type, std::asctime(std::gmtime(&tp)), rtrim(std::string(this->_symbol, 8)).c_str());
        printf("message type: %c\n", this->_msg_type);
    }

    #ifdef ENABLE_JSONCPP
    std::string  IEX_SecurityEventMsg::export_json(){
        Json::Value iex_msg;
        iex_msg["message_type"] = (char)this->_msg_type;
        iex_msg["time_stamp"] = (double)(this->_time_stamp/1e9);
        iex_msg["symbol"] = rtrim(std::string(this->_symbol, 8));
        iex_msg["security_event"] = (char)this->_flags;

        Json::StyledWriter writer;
        std::string json_str = writer.write(iex_msg);
        return json_str;
    }
    #endif

    std::string IEX_SecurityEventMsg::export_str(){
        std::stringstream sstream;
        sstream << "message_type" << " " << "char" << " " << (char)this->_msg_type <<std::endl;
        sstream << "time_stamp" << " " << "double" << " " << std::to_string((double)(this->_time_stamp/1e9)) << "\n";
        sstream << "symbol" << " " << "string" << " " << rtrim(std::string(this->_symbol, 8)) << "\n";
        sstream << "security_event" << " " << "char" << " " << (char)this->_flags << "\n";
        return sstream.str();
    }

    /*
    price level update message: Symbol "8"(0x38)-on Buy side, "5"(0x35)-on Sell side

    DEEP broadcasts a real-time Price Level Update Message each time a displayed price level on IEX is updated during the
    trading day. When a price level is removed, IEX will disseminate a size of zero (i.e., 0x0) for the level.

    parameters
        message_type(byte): "8" (0x38) - Price Level Update on the Buy Side
                            "5" (0x35) - Price Level Update on the Sell Side
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
    */
   class IEX_PriceLevelUpdateMsg:public IEX_Message{
    public:
        char _symbol[8];
        INTEGER _size;
        PRICE _price;
        IEX_PriceLevelUpdateMsg(const uint8_t * bytes);
        ~IEX_PriceLevelUpdateMsg();
        void print() override;

        #ifdef ENABLE_JSONCPP
        std::string export_json() override;
        #endif

        std::string export_str() override;
    };

    IEX_PriceLevelUpdateMsg::IEX_PriceLevelUpdateMsg(const uint8_t * bytes):IEX_Message(bytes){
        // init parameters
        //memcpy((void *)this->_symbol, bytes + IEX_BASE_MSG_SIZE, IEX_PLU_MSG_SIZE);
        memcpy((void *)this->_symbol, bytes + IEX_BASE_MSG_SIZE, 8);
        memcpy((void *)&(this->_size), bytes + IEX_BASE_MSG_SIZE + 8, 4);
        memcpy((void *)&(this->_price), bytes + IEX_BASE_MSG_SIZE + 12, 8);
    }

    IEX_PriceLevelUpdateMsg::~IEX_PriceLevelUpdateMsg(){
        // delete memory
    }

    void IEX_PriceLevelUpdateMsg::print(){
        time_t tp = this->_time_stamp/1e9;
        printf("message type: %c\ntime_stamp: %ssymbol: %s\nsize: %u, price: %f\n", this->_msg_type, std::asctime(std::gmtime(&tp)), rtrim(std::string(this->_symbol, 8)).c_str(), this->_size, (double)(this->_price/1e4));
    }

    #ifdef ENABLE_JSONCPP
    std::string  IEX_PriceLevelUpdateMsg::export_json(){
        Json::Value iex_msg;
        iex_msg["message_type"] = (char)this->_msg_type;
        iex_msg["time_stamp"] = (double)(this->_time_stamp/1e9);
        iex_msg["symbol"] = rtrim(std::string(this->_symbol, 8));
        iex_msg["event_falgs"] = this->_flags;
        iex_msg["size"] = this->_size;
        iex_msg["price"] = (double)this->_price/1e4;

        Json::StyledWriter writer;
        std::string json_str = writer.write(iex_msg);
        return json_str;
    }
    #endif

    std::string IEX_PriceLevelUpdateMsg::export_str(){
        std::stringstream sstream;
        sstream << "message_type" << " " << "char" << " " << (char)this->_msg_type <<std::endl;
        sstream << "time_stamp" << " " << "double" << " " << std::to_string((double)(this->_time_stamp/1e9)) << "\n";
        sstream << "symbol" << " " << "string" << " " << rtrim(std::string(this->_symbol, 8)) << "\n";
        sstream << "event_falgs" << " " << "uint8_t" << " " << std::to_string(this->_flags) << "\n";
        sstream << "size" << " " << "uint32_t" << " " << std::to_string(this->_size) << "\n";
        sstream << "price" << " " << "double" << " " << std::to_string((double)this->_price/1e4) << "\n";
        return sstream.str();
    }

    /*
    Quote Update Message: Symbol "Q" (0x51)

    TOPS broadcasts a real-time Quote Update Message each time IEX"s best bid or offer quotation is updated during the
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
    A (7"th bit - mask: 0x80): Symbol Availability Flag - 0: Symbol is active (available for trading), 1: Symbol is halted, paused, or otherwise not available for trading on IEX
    P (6"th bit - mask: 0x40): Market Session Flag - 0: Regular Market Session, 1: Pre/Post-Market Session
    */
   class IEX_QuoteUpdateMsg:public IEX_Message{
    public:
        char _symbol[8];
        INTEGER _bid_size;
        PRICE _bid_price;
        PRICE _ask_price;
        INTEGER _ask_size;
        IEX_QuoteUpdateMsg(const uint8_t * bytes);
        ~IEX_QuoteUpdateMsg();
        void print() override;
        std::tuple<bool, bool> _parse_flags();

        #ifdef ENABLE_JSONCPP
        std::string export_json() override;
        #endif

        std::string export_str() override;
    };

    IEX_QuoteUpdateMsg::IEX_QuoteUpdateMsg(const uint8_t * bytes):IEX_Message(bytes){
        // init parameters
        // memcpy((void *)this->_symbol, bytes + IEX_BASE_MSG_SIZE, IEX_Q_MSG_SIZE);
        memcpy((void *)this->_symbol, bytes + IEX_BASE_MSG_SIZE, 8);
        memcpy((void *)&(this->_bid_size), bytes + IEX_BASE_MSG_SIZE + 8, 4);
        memcpy((void *)&(this->_bid_price), bytes + IEX_BASE_MSG_SIZE + 12, 8);
        memcpy((void *)&(this->_ask_price), bytes + IEX_BASE_MSG_SIZE+ 20, 8);
        memcpy((void *)&(this->_ask_size), bytes + IEX_BASE_MSG_SIZE + 28, 4);
    }

    IEX_QuoteUpdateMsg::~IEX_QuoteUpdateMsg(){
        // delete memory
    }

    void IEX_QuoteUpdateMsg::print(){
        time_t tp = this->_time_stamp/1e9;
        printf("message type: %c\ntime_stamp: %ssymbol: %s\nbid_size: %u, bid price: %f\nask_size: %u, ask_price: %f\n", this->_msg_type, std::asctime(std::gmtime(&tp)), rtrim(std::string(this->_symbol, 8)).c_str(), this->_bid_size, (double)(this->_bid_price/1e4), this->_ask_size, (double)(this->_ask_price/1e4));
    }

    std::tuple<bool, bool> IEX_QuoteUpdateMsg::_parse_flags(){
        //return std::tuple<bool, bool> flags(this->_flags&0x80, this->_flags&0x40);
        return std::make_tuple (this->_flags&0x80, this->_flags&0x40);
    }

    #ifdef ENABLE_JSONCPP
    std::string  IEX_QuoteUpdateMsg::export_json(){
        Json::Value iex_msg;
        iex_msg["message_type"] = (char)this->_msg_type;
        iex_msg["time_stamp"] = (double)(this->_time_stamp/1e9);
        iex_msg["symbol"] = rtrim(std::string(this->_symbol, 8));
        iex_msg["flags"] = this->_flags;
        bool a, p;
        std::tie(a, p) = this->_parse_flags();
        iex_msg["A"] = a;
        iex_msg["P"] = p;
        //std::tie(iex_msg["A"], iex_msg["P"]) = this->_parse_flags();
        iex_msg["bid_size"] = this->_bid_size;
        iex_msg["bid_price"] = (double)this->_bid_price/1e4;
        iex_msg["ask_size"] = this->_ask_size;
        iex_msg["ask_price"] = (double)this->_ask_price/1e4;

        Json::StyledWriter writer;
        std::string json_str = writer.write(iex_msg);
        return json_str;
    }
    #endif

    std::string IEX_QuoteUpdateMsg::export_str(){
        std::stringstream sstream;
        sstream << "message_type" << " " << "char" << " " << (char)this->_msg_type <<std::endl;
        sstream << "time_stamp" << " " << "double" << " " << std::to_string((double)(this->_time_stamp/1e9)) << "\n";
        sstream << "symbol" << " " << "string" << " " << rtrim(std::string(this->_symbol, 8)) << "\n";
        sstream << "flags" << " " << "uint8_t" << " " << std::to_string(this->_flags) << "\n";
        bool a, p;
        std::tie(a, p) = this->_parse_flags();
        sstream << "A" << " " << "bool" << " " << std::to_string(a) << "\n";
        sstream << "P" << " " << "bool" << " " << std::to_string(p) << "\n";

        sstream << "bid_size" << " " << "uint32_t" << " " << std::to_string(this->_bid_size) << "\n";
        sstream << "bid_price" << " " << "double" << " " << std::to_string((double)this->_bid_price/1e4) << "\n";
        sstream << "ask_size" << " " << "uint32_t" << " " << std::to_string(this->_ask_size) << "\n";
        sstream << "ask_price" << " " << "double" << " " << std::to_string((double)this->_ask_price/1e4) << "\n";
        return sstream.str();
    }

    /*
    Trade Report Message: Symbol "T" (0x54)

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
        F (7"th bit - mask: 0x80): Intermarket Sweep Flag - 0: Non-Intermarket Sweep Order, 1: Intermarket Sweep Order
        T (6"th bit - mask: 0x40): Extended Hours Flag - 0: Regular Market Session Trade, 1: Extended Hours Trade (i.e., Form T sale condition)
        I (5"th bit - mask: 0x20): Odd Lot Flag - 0: Round or Mixed Lot Trade, 1: Odd Lot Trade
        8 (4"th bit - mask: 0x10): Trade Throught Exempt Flag - 0: Trade is subject to Rule 611 (Trade Through) of SEC Reg. NMS, 1: Trade is not subject to Rule 611 (Trade Through) of SEC Reg. NMS*
        X (3"th bit - mask: 0x08): Single-price Closs Trade Flag - 0: Execution during continuous trading, 1: Trade resulting from a single-price cross
    */
   class IEX_TradeReportMsg:public IEX_Message{
    public:
        char _symbol[8];
        INTEGER _size;
        PRICE _price;
        LONG _trade_id;
        IEX_TradeReportMsg(const uint8_t * bytes);
        ~IEX_TradeReportMsg();
        void print() override;
        std::tuple<bool, bool, bool, bool, bool> _parse_flags();

        #ifdef ENABLE_JSONCPP
        std::string export_json() override;
        #endif

        std::string export_str() override;
    };

    IEX_TradeReportMsg::IEX_TradeReportMsg(const uint8_t * bytes):IEX_Message(bytes){
        // init parameters
        //memcpy((void *)this->_symbol, bytes + IEX_BASE_MSG_SIZE, IEX_T_MSG_SIZE);
        memcpy((void *)this->_symbol, bytes + IEX_BASE_MSG_SIZE, 8);
        memcpy((void *)&(this->_size), bytes + IEX_BASE_MSG_SIZE + 8, 4);
        memcpy((void *)&(this->_price), bytes + IEX_BASE_MSG_SIZE + 12, 8);
        memcpy((void *)&(this->_trade_id), bytes + IEX_BASE_MSG_SIZE+ 20, 8);
    }

    IEX_TradeReportMsg::~IEX_TradeReportMsg(){
        // delete memory
    }

    void IEX_TradeReportMsg::print(){
        time_t tp = this->_time_stamp/1e9;
        printf("message type: %c\ntime_stamp: %ssymbol: %s\nsize: %u, price: %f\ntrade_id: %lu\n", this->_msg_type, std::asctime(std::gmtime(&tp)), rtrim(std::string(this->_symbol, 8)).c_str(), this->_size, (double)(this->_price/1e4), this->_trade_id);
    }

    std::tuple<bool, bool, bool, bool, bool> IEX_TradeReportMsg::_parse_flags(){
        //return std::tuple<bool, bool, bool, bool, bool> flags(this->_flags&0x80, this->_flags&0x40, this->_flags&0x20, this->_flags&0x10, this->_flags&0x08);
        return std::make_tuple (this->_flags&0x80, this->_flags&0x40, this->_flags&0x20, this->_flags&0x10, this->_flags&0x08);
    }

    #ifdef ENABLE_JSONCPP
    std::string  IEX_TradeReportMsg::export_json(){
        Json::Value iex_msg;
        iex_msg["message_type"] = (char)this->_msg_type;
        iex_msg["time_stamp"] = (double)(this->_time_stamp/1e9);
        iex_msg["symbol"] = rtrim(std::string(this->_symbol, 8));
        iex_msg["sale_condition_flags"] = this->_flags;
        bool f, t, i, ei, x;
        std::tie(f, t, i, ei, x) = this->_parse_flags();
        iex_msg["F"] = f; iex_msg["T"] = t; iex_msg["I"] = i; iex_msg["8"] = ei; iex_msg["X"] = x;
        //std::tie(iex_msg["F"], iex_msg["T"], iex_msg["I"], iex_msg["8"], iex_msg["X"]) = this->_parse_flags();
        iex_msg["size"] = this->_size;
        iex_msg["price"] = (double)this->_price/1e4;
        //iex_msg["trade_ID"] = this->_trade_id;

        Json::StyledWriter writer;
        std::string json_str = writer.write(iex_msg);
        return json_str;
    }
    #endif

    std::string IEX_TradeReportMsg::export_str(){
        std::stringstream sstream;
        sstream << "message_type" << " " << "char" << " " << (char)this->_msg_type <<std::endl;
        sstream << "time_stamp" << " " << "double" << " " << std::to_string((double)(this->_time_stamp/1e9)) << "\n";
        sstream << "symbol" << " " << "string" << " " << rtrim(std::string(this->_symbol, 8)) << "\n";
        sstream << "sale_condition_flags" << " " << "uint8_t" << " " << std::to_string(this->_flags) << "\n";
        bool f, t, i, ei, x;
        std::tie(f, t, i, ei, x) = this->_parse_flags();
        sstream << "F" << " " << "bool" << " " << std::to_string(f) << "\n";
        sstream << "T" << " " << "bool" << " " << std::to_string(t) << "\n";
        sstream << "I" << " " << "bool" << " " << std::to_string(i) << "\n";
        sstream << "8" << " " << "bool" << " " << std::to_string(ei) << "\n";
        sstream << "X" << " " << "bool" << " " << std::to_string(x) << "\n";

        sstream << "size" << " " << "uint32_t" << " " << std::to_string(this->_size) << "\n";
        sstream << "price" << " " << "double" << " " << std::to_string((double)this->_price/1e4) << "\n";
        sstream << "trade_ID" << " " << "uint64_t" << " " << std::to_string(this->_trade_id) << "\n";
        return sstream.str();
    }

    /*
    official price Message: Symbol "X" (0x58)

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
        • "Q" (0x51) - IEX Official Opening Price.
        • "M" (0x4d) - IEX Official Closing Price.
    */
   class IEX_OfficialPriceMsg:public IEX_Message{
    public:
        char _symbol[8];
        PRICE _official_price;
        IEX_OfficialPriceMsg(const uint8_t * bytes);
        ~IEX_OfficialPriceMsg();
        void print() override;

        #ifdef ENABLE_JSONCPP
        std::string export_json() override;
        #endif

        std::string export_str() override;
    };

    IEX_OfficialPriceMsg::IEX_OfficialPriceMsg(const uint8_t * bytes):IEX_Message(bytes){
        // init parameters
        //memcpy((void *)this->_symbol, bytes + IEX_BASE_MSG_SIZE, IEX_X_MSG_SIZE);
        memcpy((void *)this->_symbol, bytes + IEX_BASE_MSG_SIZE, 8);
        memcpy((void *)&(this->_official_price), bytes + IEX_BASE_MSG_SIZE + 8, 8);
    }

    IEX_OfficialPriceMsg::~IEX_OfficialPriceMsg(){
        // delete memory
    }

    void IEX_OfficialPriceMsg::print(){
        time_t tp = this->_time_stamp/1e9;
        printf("message type: %c\ntime_stamp: %ssymbol: %s\nofficial price: %f\n", this->_msg_type, std::asctime(std::gmtime(&tp)), rtrim(std::string(this->_symbol, 8)).c_str(), (double)(this->_official_price/1e4));
    }

    #ifdef ENABLE_JSONCPP
    std::string  IEX_OfficialPriceMsg::export_json(){
        Json::Value iex_msg;
        iex_msg["message_type"] = (char)this->_msg_type;
        iex_msg["time_stamp"] = (double)(this->_time_stamp/1e9);
        iex_msg["symbol"] = rtrim(std::string(this->_symbol, 8));
        iex_msg["price_type"] = (char)this->_flags;
        iex_msg["official_price"] = (double)this->_official_price/1e4;

        Json::StyledWriter writer;
        std::string json_str = writer.write(iex_msg);
        return json_str;
    }
    #endif

    std::string IEX_OfficialPriceMsg::export_str(){
        std::stringstream sstream;
        sstream << "message_type" << " " << "char" << " " << (char)this->_msg_type <<std::endl;
        sstream << "time_stamp" << " " << "double" << " " << std::to_string((double)(this->_time_stamp/1e9)) << "\n";
        sstream << "symbol" << " " << "string" << " " << rtrim(std::string(this->_symbol, 8)) << "\n";
        sstream << "price_type" << " " << "char" << " " << (const char)this->_flags << "\n";
        sstream << "official_price" << " " << "double" << " " << std::to_string((double)this->_official_price/1e4) << "\n";
        return sstream.str();
    }

    /*
    trade break Message: Symbol "B" (0x42)

    Trade Break Messages are sent when an execution on IEX is broken on that same trading day. Trade breaks are rare and
    only affect applications that rely upon IEX execution based data.

    Parameters
        message_type(byte): B
        sale_condition_flags(byte): flag values
        time_stamp(timestamp): Time stamp of the trade break
        symbol(string): Security identifier
        size(Integer) Trade break volume
        price(price): Trade break price
        trade_ID(long): IEX trade identifier of the trade that was broken. Trade ID refers to the previously sent Trade Report Message.

    Flags
        F (7"th bit - mask: 0x80): Intermarket Sweep Flag - 0: Non-Intermarket Sweep Order, 1: Intermarket Sweep Order
        T (6"th bit - mask: 0x40): Extended Hours Flag - 0: Regular Market Session Trade, 1: Extended Hours Trade (i.e., Form T sale condition)
        I (5"th bit - mask: 0x20): Odd Lot Flag - 0: Round or Mixed Lot Trade, 1: Odd Lot Trade
        8 (4"th bit - mask: 0x10): Trade Throught Exempt Flag - 0: Trade is subject to Rule 611 (Trade Through) of SEC Reg. NMS, 1: Trade is not subject to Rule 611 (Trade Through) of SEC Reg. NMS*
        X (3"th bit - mask: 0x08): Single-price Closs Trade Flag - 0: Execution during continuous trading, 1: Trade resulting from a single-price cross
    */
    class IEX_TradeBreakMsg:public IEX_Message{
    public:
        char _symbol[8];
        INTEGER _size;
        PRICE _price;
        LONG _trade_id;
        IEX_TradeBreakMsg(const uint8_t * bytes);
        ~IEX_TradeBreakMsg();
        void print() override;
        std::tuple<bool, bool, bool, bool, bool> _parse_flags();

        #ifdef ENABLE_JSONCPP
        std::string export_json() override;
        #endif

        std::string export_str() override;
    };

    IEX_TradeBreakMsg::IEX_TradeBreakMsg(const uint8_t * bytes):IEX_Message(bytes){
        // init parameters
        //memcpy((void *)this->_symbol, bytes + IEX_BASE_MSG_SIZE, IEX_B_MSG_SIZE);
        memcpy((void *)this->_symbol, bytes + IEX_BASE_MSG_SIZE, 8);
        memcpy((void *)&(this->_size), bytes + IEX_BASE_MSG_SIZE + 8, 4);
        memcpy((void *)&(this->_price), bytes + IEX_BASE_MSG_SIZE + 12, 8);
        memcpy((void *)&(this->_trade_id), bytes + IEX_BASE_MSG_SIZE+ 20, 8);
    }

    IEX_TradeBreakMsg::~IEX_TradeBreakMsg(){
        // delete memory
    }

    void IEX_TradeBreakMsg::print(){
        time_t tp = this->_time_stamp/1e9;
        printf("message type: %c\ntime_stamp: %ssymbol: %s\nsize: %u, price: %f\ntrade_id: %lu\n", this->_msg_type, std::asctime(std::gmtime(&tp)), rtrim(std::string(this->_symbol, 8)).c_str(), this->_size, (double)(this->_price/1e4), this->_trade_id);
    }

    std::tuple<bool, bool, bool, bool, bool> IEX_TradeBreakMsg::_parse_flags(){
        //return std::tuple<bool, bool, bool, bool, bool> flags(this->_flags&0x80, this->_flags&0x40, this->_flags&0x20, this->_flags&0x10, this->_flags&0x08);
        return std::make_tuple (this->_flags&0x80, this->_flags&0x40, this->_flags&0x20, this->_flags&0x10, this->_flags&0x08);
    }

    #ifdef ENABLE_JSONCPP
    std::string  IEX_TradeBreakMsg::export_json(){
        Json::Value iex_msg;
        iex_msg["message_type"] = (char)this->_msg_type;
        iex_msg["time_stamp"] = (double)(this->_time_stamp/1e9);
        iex_msg["symbol"] = rtrim(std::string(this->_symbol, 8));
        iex_msg["sale_condition_flags"] = this->_flags;
        bool f, t, i, ei, x;
        std::tie(f, t, i, ei, x) = this->_parse_flags();
        iex_msg["F"] = f; iex_msg["T"] = t; iex_msg["I"] = i; iex_msg["8"] = ei; iex_msg["X"] = x;
        //std::tie(iex_msg["F"], iex_msg["T"], iex_msg["I"], iex_msg["8"], iex_msg["X"]) = this->_parse_flags();
        iex_msg["size"] = this->_size;
        iex_msg["price"] = (double)this->_price/1e4;
        //iex_msg["trade_ID"] = this->_trade_id;

        Json::StyledWriter writer;
        std::string json_str = writer.write(iex_msg);
        return json_str;
    }
    #endif

    std::string IEX_TradeBreakMsg::export_str(){
        std::stringstream sstream;
        sstream << "message_type" << " " << "char" << " " << (char)this->_msg_type <<std::endl;
        sstream << "time_stamp" << " " << "double" << " " << std::to_string((double)(this->_time_stamp/1e9)) << "\n";
        sstream << "symbol" << " " << "string" << " " << rtrim(std::string(this->_symbol, 8)) << "\n";
        sstream << "sale_condition_flags" << " " << "uint8_t" << " " << std::to_string(this->_flags) << "\n";
        bool f, t, i, ei, x;
        std::tie(f, t, i, ei, x) = this->_parse_flags();
        sstream << "F" << " " << "bool" << " " << std::to_string(f) << "\n";
        sstream << "T" << " " << "bool" << " " << std::to_string(t) << "\n";
        sstream << "I" << " " << "bool" << " " << std::to_string(i) << "\n";
        sstream << "8" << " " << "bool" << " " << std::to_string(ei) << "\n";
        sstream << "X" << " " << "bool" << " " << std::to_string(x) << "\n";

        sstream << "size" << " " << "uint32_t" << " " << std::to_string(this->_size) << "\n";
        sstream << "price" << " " << "double" << " " << std::to_string((double)this->_price/1e4) << "\n";
        sstream << "trade_ID" << " " << "uint64_t" << " " << std::to_string(this->_trade_id) << "\n";
        return sstream.str();
    }

    /*
    auction information Message: Symbol "A" (0x41)

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
    */
   class IEX_AuctionInformationMsg:public IEX_Message{
    public:
        char _symbol[8];
        INTEGER _paired_shares;
        PRICE _reference_price;
        PRICE _indicative_clearing_price;
        INTEGER _imbalance_shares;
        BYTE _imbalance_side;
        BYTE _extension_number;
        EVENT_TIME _scheduled_auction_time;
        PRICE _auction_book_clearing_price;
        PRICE _collar_reference_price;
        PRICE _lower_auction_collar;
        PRICE _upper_auction_collar;
        IEX_AuctionInformationMsg(const uint8_t * bytes);
        ~IEX_AuctionInformationMsg();
        void print() override;

        #ifdef ENABLE_JSONCPP
        std::string export_json() override;
        #endif

        std::string export_str() override;
    };

    IEX_AuctionInformationMsg::IEX_AuctionInformationMsg(const uint8_t * bytes):IEX_Message(bytes){
        // init parameters
        // memcpy((void *)this->_symbol, bytes + IEX_BASE_MSG_SIZE, IEX_A_MSG_SIZE);
        memcpy((void *)this->_symbol, bytes + IEX_BASE_MSG_SIZE, 8);
        memcpy((void *)&(this->_paired_shares), bytes + IEX_BASE_MSG_SIZE + 8, 4);
        memcpy((void *)&(this->_reference_price), bytes + IEX_BASE_MSG_SIZE + 12, 8);
        memcpy((void *)&(this->_indicative_clearing_price), bytes + IEX_BASE_MSG_SIZE+ 20, 8);
        memcpy((void *)&(this->_imbalance_shares), bytes + IEX_BASE_MSG_SIZE + 28, 4);
        memcpy((void *)&(this->_imbalance_side), bytes + IEX_BASE_MSG_SIZE + 32, 1);
        memcpy((void *)&(this->_extension_number), bytes + IEX_BASE_MSG_SIZE + 33, 1);
        memcpy((void *)&(this->_scheduled_auction_time), bytes + IEX_BASE_MSG_SIZE + 34, 4);
        memcpy((void *)&(this->_auction_book_clearing_price), bytes + IEX_BASE_MSG_SIZE + 38, 8);
        memcpy((void *)&(this->_collar_reference_price), bytes + IEX_BASE_MSG_SIZE + 46, 8);
        memcpy((void *)&(this->_lower_auction_collar), bytes + IEX_BASE_MSG_SIZE + 54, 8);
        memcpy((void *)&(this->_upper_auction_collar), bytes + IEX_BASE_MSG_SIZE + 62, 8);
    }

    IEX_AuctionInformationMsg::~IEX_AuctionInformationMsg(){
        // delete memory
    }

    void IEX_AuctionInformationMsg::print(){
        time_t tp = this->_time_stamp/1e9;
        time_t stp = this->_scheduled_auction_time;
        printf("message type: %c\ntime_stamp: %ssymbol: %s\npaired_shares: %u\nreference_price: %f\nindicative_clearing_price: %f\nimbalance_shares: %u\nimbalance_side: %c\nextension_number: %u\nscheduled_auction_time: %sauction_book_clearing_price: %f\ncollar_reference_price: %f\nlower_auction_collar: %f\nupper_acution_collar: %f\n", this->_msg_type, std::asctime(std::gmtime(&tp)), rtrim(std::string(this->_symbol, 8)).c_str(), this->_paired_shares, (double)(this->_reference_price/1e4), (double)(this->_indicative_clearing_price/1e4), this->_imbalance_shares, this->_imbalance_side, this->_extension_number, std::asctime(std::gmtime(&stp)), (double)(this->_auction_book_clearing_price/1e4), (double)(this->_collar_reference_price/1e4), (double)(this->_lower_auction_collar/1e4), (double)(this->_upper_auction_collar/1e4));
    }

    #ifdef ENABLE_JSONCPP
    std::string  IEX_AuctionInformationMsg::export_json(){
        Json::Value iex_msg;
        //iex_msg["message_type"] = (char)this->_msg_type;
        iex_msg["message_type"] = this->_msg_type;
        iex_msg["time_stamp"] = (double)(this->_time_stamp/1e9);
        iex_msg["symbol"] = rtrim(std::string(this->_symbol, 8));
        iex_msg["auction_type"] = (char)this->_flags;
        iex_msg["paired_shares"] = this->_paired_shares;
        iex_msg["reference_price"] = (double)this->_reference_price/1e4;
        iex_msg["indicative_clearing_price"] = (double)this->_indicative_clearing_price/1e4;
        iex_msg["imbalance_shares"] = this->_imbalance_shares;
        iex_msg["imbalance_side"] = (char)this->_imbalance_side;
        iex_msg["extension_number"] = this->_extension_number;
        iex_msg["scheduled_auction_time"] = this->_scheduled_auction_time;
        iex_msg["auction_book_clearing_price"] = (double)this->_auction_book_clearing_price/1e4;
        iex_msg["collar_reference_price"] = (double)this->_collar_reference_price/1e4;
        iex_msg["lower_auction_collar"] = (double)this->_lower_auction_collar/1e4;
        iex_msg["upper_acution_collar"] = (double)this->_upper_auction_collar/1e4;

        Json::StyledWriter writer;
        std::string json_str = writer.write(iex_msg);
        return json_str;
    }
    #endif

    std::string IEX_AuctionInformationMsg::export_str(){
        std::stringstream sstream;
        sstream << "message_type" << " " << "char" << " " << (char)this->_msg_type <<std::endl;
        sstream << "time_stamp" << " " << "double" << " " << std::to_string((double)(this->_time_stamp/1e9)) << "\n";
        sstream << "symbol" << " " << "string" << " " << rtrim(std::string(this->_symbol, 8)) << "\n";
        sstream << "auction_type" << " " << "char" << " " << (char)this->_flags << "\n";
        sstream << "paired_shares" << " " << "uint32_t" << " " << std::to_string(this->_paired_shares) << "\n";
        sstream << "reference_price" << " " << "double" << " " << std::to_string((double)this->_reference_price/1e4) << "\n";
        sstream << "indicative_clearing_price" << " " << "double" << " " << std::to_string((double)this->_indicative_clearing_price/1e4) << "\n";
        sstream << "imbalance_shares" << " " << "uint32_t" << " " << std::to_string(this->_imbalance_shares) << "\n";
        sstream << "imbalance_side" << " " << "char" << " " << (char)this->_imbalance_side << "\n";
        sstream << "extension_number" << " " << "uint8_t" << " " << std::to_string(this->_extension_number) << "\n";
        sstream << "scheduled_auction_time" << " " << "uint32_t" << " " << std::to_string(this->_scheduled_auction_time) << "\n";
        sstream << "auction_book_clearing_price" << " " << "double" << " " << std::to_string((double)this->_auction_book_clearing_price/1e4) << "\n";
        sstream << "collar_reference_price" << " " << "double" << " " << std::to_string((double)this->_collar_reference_price/1e4) << "\n";
        sstream << "lower_auction_collar" << " " << "double" << " " << std::to_string((double)this->_lower_auction_collar/1e4) << "\n";
        sstream << "upper_acution_collar" << " " << "double" << " " << std::to_string((double)this->_upper_auction_collar/1e4) << "\n";
        return sstream.str();
    }

    /*
    ------------------------------------------------------------
    IEX_Packet
    */


    class IEX_Packet{
    public:
        IEX_Packet();
        IEX_Packet(const uint8_t * bytes);
        ~IEX_Packet();
        int set_header(const uint8_t * bytes);
        std::shared_ptr<IEX_Message> create_message(const uint8_t * bytes);
        std::vector<std::shared_ptr<IEX_Message> > get_messages(const uint8_t * bytes);
        std::vector<std::shared_ptr<IEX_Message> > parse_and_get_messages(const uint8_t * bytes);
        std::vector<std::shared_ptr<IEX_Message> > parse_messages(const uint8_t * bytes);
    private:
        BYTE _ver; // 1 byte
        BYTE _reserved; // 1 byte
        SHORT _msg_protocol_id; // 2 bytes
        INTEGER _channel_id; // 4 bytes
        INTEGER _session_id; // 4 bytes
        SHORT _payload_len; // 2 bytes
        SHORT _msg_cnt; // 2 bytes
        LONG _stream_offset; // 8 bytes
        LONG _first_msg_seq_num; // 8 bytes
        TIME_STAMP _time_stamp; // 8 bytes
    };

    IEX_Packet::IEX_Packet(){
        // parsing
    }

    IEX_Packet::IEX_Packet(const uint8_t * bytes){
        // parsing test
        memcpy((void *)&(this->_ver), bytes, IEX_TP_HEADER_SIZE);
    }

    IEX_Packet::~IEX_Packet(){
        // delete memory
    }

    int IEX_Packet::set_header(const uint8_t * bytes){
        // parsing test
        memcpy((void *)&(this->_ver), bytes, IEX_TP_HEADER_SIZE);
        return 0;
    }

    std::vector<std::shared_ptr<IEX_Message> > IEX_Packet::get_messages(const uint8_t * bytes){
        // return massage
        return this->parse_messages(bytes);
    }

    std::vector<std::shared_ptr<IEX_Message> > IEX_Packet::parse_and_get_messages(const uint8_t * bytes){
        // parse and get message
        this->set_header(bytes);
        return this->parse_messages(bytes);
    }

    std::vector<std::shared_ptr<IEX_Message> > IEX_Packet::parse_messages(const uint8_t * bytes){
        std::vector<std::shared_ptr<IEX_Message> > messages;

        // parse message
        size_t offset = IEX_TP_HEADER_SIZE;
        SHORT msg_len;
        size_t short_size = 2;
        //size_t short_size = sizeof(SHORT);
        for(int i=0; i < this->_msg_cnt; i++){
            // get a length of a message
             memcpy((void *)&(msg_len), bytes + offset, short_size);
             // create message
             messages.push_back(this->create_message(bytes + offset + short_size));
             //printf("message type: %c\n", obj._msg_type);
             offset += msg_len + short_size;
        }
        return messages;
    }

    /*
    S: IEX_SystemEventMsg
    D: IEX_SecurityDerectoryMsg
    H: IEX_TradingStatusMsg
    O: IEX_OperationalHaltStatusMsg
    P: IEX_ShortSalePriceTestStatusMsg
    E: IEX_SecurityEventMsg
    8: IEX_PriceLevelUpdateMsg
    5: IEX_PriceLevelUpdateMsg
    Q: IEX_QuoteUpdateMsg
    T: IEX_TradeReportMsg
    X: IEX_OfficialPriceMsg
    B: IEX_TradeBreakMsg
    A: IEX_AuctionInformationMsg
    */

    std::shared_ptr<IEX_Message> IEX_Packet::create_message(const uint8_t * bytes){
        char msg_type = (char)bytes[0];
        //printf("create_message::message type: %c\n", msg_type);
        switch (msg_type)
        {
        case 'S':
            return std::dynamic_pointer_cast<IEX_Message>(std::make_shared<IEX_SystemEventMsg>(bytes));
        case 'D':
            return std::dynamic_pointer_cast<IEX_Message>(std::make_shared<IEX_SecurityDerectoryMsg>(bytes));
        case 'H':
            return std::dynamic_pointer_cast<IEX_Message>(std::make_shared<IEX_TradingStatusMsg>(bytes));
        case 'O':
            return std::dynamic_pointer_cast<IEX_Message>(std::make_shared<IEX_OperationalHaltStatusMsg>(bytes));
        case 'P':
            return std::dynamic_pointer_cast<IEX_Message>(std::make_shared<IEX_ShortSalePriceTestStatusMsg>(bytes));
        case 'E':
            return std::dynamic_pointer_cast<IEX_Message>(std::make_shared<IEX_SecurityEventMsg>(bytes));
        case '8':
            return std::dynamic_pointer_cast<IEX_Message>(std::make_shared<IEX_PriceLevelUpdateMsg>(bytes));
        case '5':
            return std::dynamic_pointer_cast<IEX_Message>(std::make_shared<IEX_PriceLevelUpdateMsg>(bytes));
        case 'Q':
            return std::dynamic_pointer_cast<IEX_Message>(std::make_shared<IEX_QuoteUpdateMsg>(bytes));
        case 'T':
            return std::dynamic_pointer_cast<IEX_Message>(std::make_shared<IEX_TradeReportMsg>(bytes));
        case 'X':
            return std::dynamic_pointer_cast<IEX_Message>(std::make_shared<IEX_OfficialPriceMsg>(bytes));
        case 'B':
            return std::dynamic_pointer_cast<IEX_Message>(std::make_shared<IEX_TradeBreakMsg>(bytes));
        case 'A':
            return std::dynamic_pointer_cast<IEX_Message>(std::make_shared<IEX_AuctionInformationMsg>(bytes));
        default:
            return NULL;
        }
    }
}


