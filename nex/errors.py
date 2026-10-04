from __future__ import annotations


ERROR_MASK = 1 << 31


class NexError(Exception):
    pass


class Core:
    Unknown = 0x00010001
    NotImplemented = 0x00010002
    InvalidPointer = 0x00010003
    OperationAborted = 0x00010004
    Exception = 0x00010005
    AccessDenied = 0x00010006
    InvalidHandle = 0x00010007
    InvalidIndex = 0x00010008
    OutOfMemory = 0x00010009
    InvalidArgument = 0x0001000A
    Timeout = 0x0001000B
    InitializationFailure = 0x0001000C
    CallInitiationFailure = 0x0001000D
    RegistrationError = 0x0001000E
    BufferOverflow = 0x0001000F
    InvalidLockState = 0x00010010
    InvalidSequence = 0x00010011
    SystemError = 0x00010012
    Cancelled = 0x00010013


class DDL:
    InvalidSignature = 0x00020001
    IncorrectVersion = 0x00020002


class RendezVous:
    ConnectionFailure = 0x00030001
    NotAuthenticated = 0x00030002
    InvalidUsername = 0x00030064
    InvalidPassword = 0x00030065
    UsernameAlreadyExists = 0x00030066
    AccountDisabled = 0x00030067
    AccountExpired = 0x00030068
    ConcurrentLoginDenied = 0x00030069
    EncryptionFailure = 0x0003006A
    InvalidPID = 0x0003006B
    MaxConnectionsReached = 0x0003006C
    InvalidGID = 0x0003006D
    InvalidControlScriptID = 0x0003006E
    InvalidOperationInLiveEnvironment = 0x0003006F
    DuplicateEntry = 0x00030070
    ControlScriptFailure = 0x00030071
    ClassNotFound = 0x00030072
    SessionVoid = 0x00030073
    DDLMismatch = 0x00030075
    InvalidConfiguration = 0x00030076
    SessionFull = 0x000300C8
    InvalidGatheringPassword = 0x000300C9
    WithoutParticipationPeriod = 0x000300CA
    PersistentGatheringCreationMax = 0x000300CB
    PersistentGatheringParticipationMax = 0x000300CC
    DeniedByParticipants = 0x000300CD
    ParticipantInBlackList = 0x000300CE
    GameServerMaintenance = 0x000300CF
    OperationPostpone = 0x000300D0
    OutOfRatingRange = 0x000300D1
    ConnectionDisconnected = 0x000300D2
    InvalidOperation = 0x000300D3
    NotParticipatedGathering = 0x000300D4
    MatchmakeSessionUserPasswordUnmatch = 0x000300D5
    MatchmakeSessionSystemPasswordUnmatch = 0x000300D6
    UserIsOffline = 0x000300D7
    AlreadyParticipatedGathering = 0x000300D8
    PermissionDenied = 0x000300D9
    NotFriend = 0x000300DA
    SessionClosed = 0x000300DB
    DatabaseTemporarilyUnavailable = 0x000300DC
    InvalidUniqueId = 0x000300DD
    MatchmakingWithdrawn = 0x000300DE
    LimitExceeded = 0x000300DF
    AccountTemporarilyDisabled = 0x000300E0
    PartiallyServiceClosed = 0x000300E1
    ConnectionDisconnectedForConcurrentLogin = 0x000300E2


class PythonCore:
    Exception = 0x00040001
    TypeError = 0x00040002
    IndexError = 0x00040003
    InvalidReference = 0x00040004
    CallFailure = 0x00040005
    MemoryError = 0x00040006
    KeyError = 0x00040007
    OperationError = 0x00040008
    ConversionError = 0x00040009
    ValidationError = 0x0004000A


class Transport:
    Unknown = 0x00050001
    ConnectionFailure = 0x00050002
    InvalidUrl = 0x00050003
    InvalidKey = 0x00050004
    InvalidURLType = 0x00050005
    DuplicateEndpoint = 0x00050006
    IOError = 0x00050007
    Timeout = 0x00050008
    ConnectionReset = 0x00050009
    IncorrectRemoteAuthentication = 0x0005000A
    ServerRequestError = 0x0005000B
    DecompressionFailure = 0x0005000C
    ReliableSendBufferFullFatal = 0x0005000D
    UPnPCannotInit = 0x0005000E
    UPnPCannotAddMapping = 0x0005000F
    NatPMPCannotInit = 0x00050010
    NatPMPCannotAddMapping = 0x00050011
    UnsupportedNAT = 0x00050013
    DnsError = 0x00050014
    ProxyError = 0x00050015
    DataRemaining = 0x00050016
    NoBuffer = 0x00050017
    NotFound = 0x00050018
    TemporaryServerError = 0x00050019
    PermanentServerError = 0x0005001A
    ServiceUnavailable = 0x0005001B
    ReliableSendBufferFull = 0x0005001C
    InvalidStation = 0x0005001D
    InvalidSubStreamID = 0x0005001E
    PacketBufferFull = 0x0005001F
    NatTraversalError = 0x00050020
    NatCheckError = 0x00050021


class DOCore:
    StationNotReached = 0x00060001
    TargetStationDisconnect = 0x00060002
    LocalStationLeaving = 0x00060003
    ObjectNotFound = 0x00060004
    InvalidRole = 0x00060005
    CallTimeout = 0x00060006
    RMCDispatchFailed = 0x00060007
    MigrationInProgress = 0x00060008
    NoAuthority = 0x00060009
    NoTargetStationSpecified = 0x0006000A
    JoinFailed = 0x0006000B
    JoinDenied = 0x0006000C
    ConnectivityTestFailed = 0x0006000D
    Unknown = 0x0006000E
    UnfreedReferences = 0x0006000F
    JobTerminationFailed = 0x00060010
    InvalidState = 0x00060011
    FaultRecoveryFatal = 0x00060012
    FaultRecoveryJobProcessFailed = 0x00060013
    StationInconsitency = 0x00060014
    AbnormalMasterState = 0x00060015
    VersionMismatch = 0x00060016


class FPD:
    NotInitialized = 0x00650000
    AlreadyInitialized = 0x00650001
    NotConnected = 0x00650002
    Connected = 0x00650003
    InitializationFailure = 0x00650004
    OutOfMemory = 0x00650005
    RmcFailed = 0x00650006
    InvalidArgument = 0x00650007
    InvalidLocalAccountID = 0x00650008
    InvalidPrincipalID = 0x00650009
    InvalidLocalFriendCode = 0x0065000A
    LocalAccountNotExists = 0x0065000B
    LocalAccountNotLoaded = 0x0065000C
    LocalAccountAlreadyLoaded = 0x0065000D
    FriendAlreadyExists = 0x0065000E
    FriendNotExists = 0x0065000F
    FriendNumMax = 0x00650010
    NotFriend = 0x00650011
    FileIO = 0x00650012
    P2PInternetProhibited = 0x00650013
    Unknown = 0x00650014
    InvalidState = 0x00650015
    AddFriendProhibited = 0x00650017
    InvalidAccount = 0x00650019
    BlacklistedByMe = 0x0065001A
    FriendAlreadyAdded = 0x0065001C
    MyFriendListLimitExceed = 0x0065001D
    RequestLimitExceed = 0x0065001E
    InvalidMessageID = 0x0065001F
    MessageIsNotMine = 0x00650020
    MessageIsNotForMe = 0x00650021
    FriendRequestBlocked = 0x00650022
    NotInMyFriendList = 0x00650023
    FriendListedByMe = 0x00650024
    NotInMyBlacklist = 0x00650025
    IncompatibleAccount = 0x00650026
    BlockSettingChangeNotAllowed = 0x00650027
    SizeLimitExceeded = 0x00650028
    OperationNotAllowed = 0x00650029
    NotNetworkAccount = 0x0065002A
    NotificationNotFound = 0x0065002B
    PreferenceNotInitialized = 0x0065002C
    FriendRequestNotAllowed = 0x0065002D


class Ranking:
    NotInitialized = 0x00670001
    InvalidArgument = 0x00670002
    RegistrationError = 0x00670003
    NotFound = 0x00670005
    InvalidScore = 0x00670006
    InvalidDataSize = 0x00670007
    PermissionDenied = 0x00670009
    Unknown = 0x0067000A
    NotImplemented = 0x0067000B


class Authentication:
    NASAuthenticateError = 0x00680001
    TokenParseError = 0x00680002
    HttpConnectionError = 0x00680003
    HttpDNSError = 0x00680004
    HttpGetProxySetting = 0x00680005
    TokenExpired = 0x00680006
    ValidationFailed = 0x00680007
    InvalidParam = 0x00680008
    PrincipalIdUnmatched = 0x00680009
    MoveCountUnmatch = 0x0068000A
    UnderMaintenance = 0x0068000B
    UnsupportedVersion = 0x0068000C
    ServerVersionIsOld = 0x0068000D
    Unknown = 0x0068000E
    ClientVersionIsOld = 0x0068000F
    AccountLibraryError = 0x00680010
    ServiceNoLongerAvailable = 0x00680011
    UnknownApplication = 0x00680012
    ApplicationVersionIsOld = 0x00680013
    OutOfService = 0x00680014
    NetworkServiceLicenseRequired = 0x00680015
    NetworkServiceLicenseSystemError = 0x00680016
    NetworkServiceLicenseError3 = 0x00680017
    NetworkServiceLicenseError4 = 0x00680018


class DataStore:
    Unknown = 0x00690001
    InvalidArgument = 0x00690002
    PermissionDenied = 0x00690003
    NotFound = 0x00690004
    AlreadyLocked = 0x00690005
    UnderReviewing = 0x00690006
    Expired = 0x00690007
    InvalidCheckToken = 0x00690008
    SystemFileError = 0x00690009
    OverCapacity = 0x0069000A
    OperationNotAllowed = 0x0069000B
    InvalidPassword = 0x0069000C
    ValueNotEqual = 0x0069000D


class ServiceItem:
    Unknown = 0x006C0001
    InvalidArgument = 0x006C0002
    EShopUnknownHttpError = 0x006C0003
    EShopResponseParseError = 0x006C0004
    NotOwned = 0x006C0005
    InvalidLimitationType = 0x006C0006
    ConsumptionRightShortage = 0x006C0007


class MatchmakeReferee:
    Unknown = 0x006F0001
    InvalidArgument = 0x006F0002
    AlreadyExists = 0x006F0003
    NotParticipatedGathering = 0x006F0004
    NotParticipatedRound = 0x006F0005
    StatsNotFound = 0x006F0006
    RoundNotFound = 0x006F0007
    RoundArbitrated = 0x006F0008
    RoundNotArbitrated = 0x006F0009


class Subscriber:
    Unknown = 0x00700001
    InvalidArgument = 0x00700002
    OverLimit = 0x00700003
    PermissionDenied = 0x00700004


class Ranking2:
    Unknown = 0x00710001
    InvalidArgument = 0x00710002
    InvalidScore = 0x00710003


class SmartDeviceVoiceChat:
    Unknown = 0x00720001
    InvalidArgument = 0x00720002
    InvalidResponse = 0x00720003
    InvalidAccessToken = 0x00720004
    Unauthorized = 0x00720005
    AccessError = 0x00720006
    UserNotFound = 0x00720007
    RoomNotFound = 0x00720008
    RoomNotActivated = 0x00720009
    ApplicationNotSupported = 0x0072000A
    InternalServerError = 0x0072000B
    ServiceUnavailable = 0x0072000C
    UnexpectedError = 0x0072000D
    UnderMaintenance = 0x0072000E
    ServiceNoLongerAvailable = 0x0072000F
    AccountTemporarilyDisabled = 0x00720010
    PermissionDenied = 0x00720011
    NetworkServiceLicenseRequired = 0x00720012
    AccountLibraryError = 0x00720013
    GameModeNotFound = 0x00720014


class Screening:
    Unknown = 0x00730001
    InvalidArgument = 0x00730002
    NotFound = 0x00730003


class Custom:
    Unknown = 0x00740001


class Ess:
    Unknown = 0x00750001
    GameSessionError = 0x00750002
    GameSessionMaintenance = 0x00750003


class Errors:
    Core = Core
    DDL = DDL
    RendezVous = RendezVous
    PythonCore = PythonCore
    Transport = Transport
    DOCore = DOCore
    FPD = FPD
    Ranking = Ranking
    Authentication = Authentication
    DataStore = DataStore
    ServiceItem = ServiceItem
    MatchmakeReferee = MatchmakeReferee
    Subscriber = Subscriber
    Ranking2 = Ranking2
    SmartDeviceVoiceChat = SmartDeviceVoiceChat
    Screening = Screening
    Custom = Custom
    Ess = Ess


_CATEGORIES = (Core, DDL, RendezVous, PythonCore, Transport, DOCore, FPD, Ranking, Authentication, DataStore, ServiceItem, MatchmakeReferee, Subscriber, Ranking2, SmartDeviceVoiceChat, Screening, Custom, Ess,)


ERROR_NAMES: dict[int, str] = {}
for _cat in _CATEGORIES:
    for _name, _code in vars(_cat).items():
        if not _name.startswith("_"):
            ERROR_NAMES[_code] = f"{_cat.__name__}::{_name}"


def error_name_from_code(error_code: int) -> str:
    name = ERROR_NAMES.get(error_code, "")
    if name == "":
        return "Invalid Error Code: " + str(error_code)
    return name
