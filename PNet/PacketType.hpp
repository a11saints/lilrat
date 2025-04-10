#pragma once
#include <stdint.h>

namespace PNet {
	enum PacketType : uint16_t {
		PT_Invalid,
		PT_ChatMessage,
		PT_IntegerArray,
		PT_Command,
		PT_Shell,
		PT_Instruction,
		PT_FileTransferRequest,
		PT_FiletransferSize,
		PT_FileTransferData,
		PT_FileTransferEnd,
	};
}