# High Level Analyzer
# For more information and documentation, please go to https://support.saleae.com/extensions/high-level-analyzer-extensions

from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, NumberSetting
from saleae.data import GraphTimeDelta
from enum import Enum

import typing

# High level analyzers must subclass the HighLevelAnalyzer class.

FRAME_TYPE_MASK = 0x80
REQ_TYPE_MASK = 0x70
REQ_DATA_SIZE_MASK = 0x07
RES_DATA_SIZE_MASK = 0x7f

COMMAND_FRAME = 0x80
RESPONSE_FRAME = 0x00
ERROR_FRAME = 0xff

SINGLE_DEVICE_READ = 0x00
SINGLE_DEVICE_WRITE = 0x10
STACK_READ = 0x20
STACK_WRITE = 0x30
BROADCAST_READ = 0x40
BROADCAST_WRITE = 0x50
BROADCAST_WRITE_REVERSE = 0x60

FRAME_TYPE_MAP = {
    COMMAND_FRAME: 'Command',
    RESPONSE_FRAME: 'Response',
}

COMMAND_TYPE_MAP = {
    SINGLE_DEVICE_READ: 'Single Device Read',
    SINGLE_DEVICE_WRITE: 'Single Device Write',
    STACK_READ: 'Stack Read',
    STACK_WRITE: 'Stack Write',
    BROADCAST_READ: 'Broadcast Read',
    BROADCAST_WRITE: 'Broadcast Write',
    BROADCAST_WRITE_REVERSE: 'Broadcast Write Reverse',
}


class TransferState(Enum):
    WAIT_INIT = 0
    WAIT_DEV_ADDR = 1
    WAIT_REG_ADDR_1 = 2
    WAIT_REG_ADDR_2 = 3
    WAIT_DATA = 4
    WAIT_CRC_1 = 5
    WAIT_CRC_2 = 6


class analyzer(HighLevelAnalyzer):

    frame_timeout = NumberSetting(label='Frame Timeout [s]', min_value=0)

    result_types = {
        'frame': {
            'format': '{{data.message}}'
        },
        'error': {
            'format': 'Error - Reason: {{data.error_reason}}'
        }
    }

    def __init__(self):
        '''
        Initialize HLA.

        Settings can be accessed using the same name used above.
        '''
        self.currentState = TransferState.WAIT_INIT

    def initPacket(self):
        self.lastPacketType = 0
        self.lastPacketTime = None
        self.lastPacketChecksum = 0
        self.lastPacketData = ""
        self.lastPacketDataSize = 0
        self.lastPacketCommandType = 0
        self.lastPacketDeviceAddress = 0
        self.lastPacketRegisterAddress = 0

    def onReceived(self, frame: AnalyzerFrame) -> AnalyzerFrame:
        data: bytes = frame.data.get('data', None)
        result: typing.Union[AnalyzerFrame, None] = None

        if data is None:
            return None

        if self.currentState != TransferState.WAIT_INIT:
            if self.lastPacketTime + GraphTimeDelta(float(self.frame_timeout)) < frame.end_time:
                self.currentState = TransferState.WAIT_INIT
                return AnalyzerFrame('error_frame', self.lastPacketTime, frame.end_time, {
                    'error_reason': 'Transfer Timeout'
                })

        for byte in data:
            '''
            Waiting for packet header
            '''
            if self.currentState == TransferState.WAIT_INIT:
                self.initPacket()
                self.lastPacketTime = frame.start_time
                # Check for frame type
                if byte & FRAME_TYPE_MASK == COMMAND_FRAME:
                    '''
                    Command frame is arriving
                    '''
                    self.lastPacketType = COMMAND_FRAME
                    self.lastPacketDataSize = (byte & REQ_DATA_SIZE_MASK) + 1
                    command = (byte & REQ_TYPE_MASK)
                    if command == SINGLE_DEVICE_READ or command == SINGLE_DEVICE_WRITE:
                        self.currentState = TransferState.WAIT_DEV_ADDR
                    else:
                        self.currentState = TransferState.WAIT_REG_ADDR_1
                    self.lastPacketCommandType = command
                else:
                    '''
                    Response frame is arriving
                    '''
                    self.lastPacketType = RESPONSE_FRAME
                    self.lastPacketDataSize = (byte & RES_DATA_SIZE_MASK) + 1
                    self.currentState = TransferState.WAIT_DEV_ADDR
                return None
            '''
            Waiting for device address
            '''
            if self.currentState == TransferState.WAIT_DEV_ADDR:
                self.lastPacketDeviceAddress = byte
                self.currentState = TransferState.WAIT_REG_ADDR_1
                return None
            '''
            Waiting for target register address
            '''
            if self.currentState == TransferState.WAIT_REG_ADDR_1:
                self.lastPacketRegisterAddress = byte << 8
                self.currentState = TransferState.WAIT_REG_ADDR_2
                return None
            if self.currentState == TransferState.WAIT_REG_ADDR_2:
                self.lastPacketRegisterAddress = self.lastPacketRegisterAddress | byte
                self.currentState = TransferState.WAIT_DATA
                return None
            '''
            Waiting for packet payload
            '''
            if self.currentState == TransferState.WAIT_DATA:
                self.lastPacketData += '0x{:02X} '.format(byte)
                self.lastPacketDataSize -= 1
                if self.lastPacketDataSize <= 0:
                    self.currentState = TransferState.WAIT_CRC_1
                return None
            '''
            Waiting for packet checkum
            '''
            if self.currentState == TransferState.WAIT_CRC_1:
                self.lastPacketChecksum = (byte << 8)
                self.currentState = TransferState.WAIT_CRC_2
                return None
            if self.currentState == TransferState.WAIT_CRC_2:
                self.lastPacketChecksum = (self.lastPacketChecksum | byte)
                self.currentState = TransferState.WAIT_INIT
                result = self.formatResult(frame)

        return result

    def formatResult(self, frame: AnalyzerFrame) -> AnalyzerFrame:
        frameMessage: str = '{:s} - '.format(
            FRAME_TYPE_MAP[self.lastPacketType])

        if (self.lastPacketType == COMMAND_FRAME):
            frameMessage += '{:s} '.format(
                COMMAND_TYPE_MAP[self.lastPacketCommandType])

        if ((self.lastPacketType == COMMAND_FRAME) and ((self.lastPacketCommandType == SINGLE_DEVICE_WRITE) or (self.lastPacketCommandType == SINGLE_DEVICE_READ))) or (self.lastPacketType == RESPONSE_FRAME):
            frameMessage += 'Device: 0x{:04X} '.format(
                self.lastPacketDeviceAddress)

        frameMessage += 'Register: 0x{:04X} Data: {:s}'.format(
            self.lastPacketRegisterAddress, self.lastPacketData)

        return AnalyzerFrame('frame', self.lastPacketTime, frame.end_time, {
            'message': frameMessage
        })

    def decode(self, frame: AnalyzerFrame):
        '''
        Process a frame from the input analyzer, and optionally return a single `AnalyzerFrame` or a list of `AnalyzerFrame`s.

        The type and data values in `frame` will depend on the input analyzer.
        '''
        if frame.type != 'data':
            # Only care about data frame
            return
        if 'error' in frame.data:
            # Ignore error frames (i.e. framing / parity errors)
            return
        return self.onReceived(frame)

        # Return the data frame itself
        # return AnalyzerFrame('mytype', frame.start_time, frame.end_time, str(data))
