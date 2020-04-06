#include "ipc_c2h_events.h"
#include "sph_log.h"
#include "sph_error.h"
#include <linux/slab.h>
#include "ipc_protocol.h"

#ifdef _DEBUG
const char *event_code_name(u32 eventCode)
{
	switch (eventCode) {
	case SPH_IPC_CREATE_CONTEXT_SUCCESS:
		return "CREATE_CONTEXT_SUCCESS";
	case SPH_IPC_CREATE_DEVRES_SUCCESS:
		return "CREATE_DEVRES_SUCCESS";
	case SPH_IPC_CREATE_CMD_SUCCESS:
		return "CREATE_CMD_SUCCESS";
	case SPH_IPC_CREATE_COPY_SUCCESS:
		return "CREATE_COPY_SUCCESS";
	case SPH_IPC_EXECUTE_COPY_SUCCESS:
		return "EXECUTE_COPY_SUCCESS";
	case SPH_IPC_EXECUTE_CPYLST_SUCCESS:
		return "EXECUTE_CPYLST_SUCCESS";
	case SPH_IPC_EXECUTE_CMD_COMPLETE:
		return "EXECUTE_CMD_COMPLETE";
	case SPH_IPC_DEVRES_DESTROYED:
		return "DEVRES_DESTROYED";
	case SPH_IPC_CMD_DESTROYED:
		return "CMD_DESTROYED";
	case SPH_IPC_COPY_DESTROYED:
		return "COPY_DESTROYED";
	case SPH_IPC_CONTEXT_DESTROYED:
		return "CONTEXT_DESTROYED";
	case SPH_IPC_CREATE_DEVNET_SUCCESS:
		return "CREATE_DEVNET_SUCCESS";
	case SPH_IPC_DEVNET_DESTROYED:
		return "DEVNET_DESTROYED";
	case SPH_IPC_CREATE_INFREQ_SUCCESS:
		return "CREATE_INFREQ_SUCCESS";
	case SPH_IPC_INFREQ_DESTROYED:
		return "INFREQ_DESTROYED";
	case SPH_IPC_RECOVER_CONTEXT_SUCCESS:
		return "RECOVER_CONTEXT_SUCCESS";
	case SPH_IPC_THERMAL_TRIP_EVENT:
		return "THERMAL_TRIP_EVENT";
	case SPH_IPC_DEVNET_ADD_RES_SUCCESS:
		return "DEVNET_ADD_RES_SUCCESS";
	case SPH_IPC_DEVICE_STATE_CHANGED:
		return "DEVICE_STATE_CHANGED";
	case SPH_IPC_CREATE_CONTEXT_FAILED:
		return "CREATE_CONTEXT_FAILED";
	case SPH_IPC_CREATE_DEVRES_FAILED:
		return "CREATE_DEVRES_FAILED";
	case SPH_IPC_CREATE_CMD_FAILED:
		return "CREATE_CMD_FAILED";
	case SPH_IPC_CREATE_COPY_FAILED:
		return "CREATE_COPY_FAILED";
	case SPH_IPC_DESTROY_CONTEXT_FAILED:
		return "DESTROY_CONTEXT_FAILED";
	case SPH_IPC_DESTROY_DEVRES_FAILED:
		return "DESTROY_DEVRES_FAILED";
	case SPH_IPC_DESTROY_CMD_FAILED:
		return "DESTROY_CMD_FAILED";
	case SPH_IPC_DESTROY_COPY_FAILED:
		return "DESTROY_COPY_FAILED";
	case SPH_IPC_CREATE_SYNC_FAILED:
		return "CREATE_SYNC_FAILED";
	case SPH_IPC_ERROR_SUB_RESOURCE_LOAD_FAILED:
		return "ERROR_SUB_RESOURCE_LOAD_FAILED";
	case SPH_IPC_CREATE_DEVNET_FAILED:
		return "CREATE_DEVNET_FAILED";
	case SPH_IPC_DESTROY_DEVNET_FAILED:
		return "DESTROY_DEVNET_FAILED";
	case SPH_IPC_CREATE_INFREQ_FAILED:
		return "CREATE_INFREQ_FAILED";
	case SPH_IPC_DESTROY_INFREQ_FAILED:
		return "DESTROY_INFREQ_FAILED";
	case SPH_IPC_RECOVER_CONTEXT_FAILED:
		return "RECOVER_CONTEXT_FAILED";
	case SPH_IPC_ERROR_MCE_CORRECTABLE:
		return "ERROR_MCE_CORRECTABLE";
	case SPH_IPC_ERROR_MCE_UNCORRECTABLE:
		return "ERROR_MCE_UNCORRECTABLE";
	case SPH_IPC_ERROR_RUNTIME_LAUNCH:
		return "ERROR_RUNTIME_LAUNCH";
	case SPH_IPC_ERROR_RUNTIME_DIED:
		return "ERROR_RUNTIME_DIED";
	case SPH_IPC_EXECUTE_COPY_FAILED:
		return "EXECUTE_COPY_FAILED";
	case SPH_IPC_EXECUTE_CPYLST_FAILED:
		return "EXECUTE_CPYLST_FAILED";
	case SPH_IPC_SCHEDULE_INFREQ_FAILED:
		return "SCHEDULE_INFREQ_FAILED";
	case SPH_IPC_ERROR_OS_CRASHED:
		return "ERROR_OS_CRASHED";
	case SPH_IPC_ERROR_PCI_ERROR:
		return "ERROR_PCI_ERROR";
	case SPH_IPC_ERROR_CARD_RESET:
		return "ERROR_CARD_RESET";
	case SPH_IPC_ERROR_MCE_UNCORRECTABLE_FATAL:
		return "ERROR_MCE_UNCORRECTABLE_FATAL";
	case SPH_IPC_DEVNET_RESOURCES_RESERVATION_SUCCESS:
		return "DEVNET_RESERVATION_SUCCESS";
	case SPH_IPC_DEVNET_RESOURCES_RESERVATION_FAILED:
		return "DEVNET_RESERVATION_FAILED";
	case SPH_IPC_DEVNET_RESOURCES_RELEASE_SUCCESS:
		return "DEVNET_RESOURCES_RELEASE_SUCCESS";
	case SPH_IPC_DEVNET_RESOURCES_RELEASE_FAILED:
		return "DEVNET_RESOURCES_RELEASE_FAILED";
	case SPH_IPC_CREATE_CHANNEL_SUCCESS:
		return "CREATE_CHANNEL_SUCCESS";
	case SPH_IPC_CHANNEL_DESTROYED:
		return "CREATE_CHANNEL_DESTROYED";
	case SPH_IPC_CREATE_CHANNEL_FAILED:
		return "CREATE_CHANNEL_FAILED";
	case SPH_IPC_DESTROY_CHANNEL_FAILED:
		return "DESTROY_CHANNEL_FAILED";
	case SPH_IPC_GET_FIFO:
		return "GET_FIFO";
	case SPH_IPC_CHANNEL_SET_RB_SUCCESS:
		return "CHANNEL_SET_RB_SUCCESS";
	case SPH_IPC_CHANNEL_SET_RB_FAILED:
		return "CHANNEL_SET_RB_FAILED";
	case SPH_IPC_CHANNEL_MAP_HOSTRES_SUCCESS:
		return "CHANNEL_MAP_HOSTRES_SUCCESS";
	case SPH_IPC_CHANNEL_MAP_HOSTRES_FAILED:
		return "CHANNEL_MAP_HOSTRES_FAILED";
	case SPH_IPC_CHANNEL_UNMAP_HOSTRES_SUCCESS:
		return "CHANNEL_UNMAP_HOSTRES_SUCCESS";
	case SPH_IPC_CHANNEL_UNMAP_HOSTRES_FAILED:
		return "CHANNEL_UNMAP_HOSTRES_FAILED";
	case SPH_IPC_DEVNET_SET_PROPERTY_SUCCESS:
		return "DEVNET_SET_PROPERTY_SUCCESS";
	case SPH_IPC_DEVNET_SET_PROPERTY_FAILED:
		return "DEVNET_SET_PROPERTY_FAILED";
	case SPH_IPC_ERROR_DRAM_ECC_UNCORRECTABLE_FATAL:
		return "SPH_IPC_ERROR_DRAM_ECC_UNCORRECTABLE_FATAL";
	case SPH_IPC_CTX_DRAM_ECC_UNCORRECTABLE:
		return "SPH_IPC_CTX_DRAM_ECC_UNCORRECTABLE";
	case SPH_IPC_ERROR_DRAM_ECC_CORRECTABLE:
		return "SPH_IPC_ERROR_DRAM_ECC_CORRECTABLE";
	case SPH_IPC_CONTEXT_EXEC_ERROR:
		return "SPH_IPC_CONTEXT_EXEC_ERROR";
	case SPH_IPC_ERROR_FATAL_ICE_ERROR:
		return "SPH_IPC_ERROR_FATAL_ICE_ERROR";
	default:
		return "Unknown event code";
	}
}

void log_c2h_event(const char *msg, const union c2h_EventReport *ev)
{
	sph_log_debug(IPC_LOG, "%s: %s(%u) val=%u ctx_id=%u (valid=%u) objID=%u (valid=%u) objID_2=%u (valid=%u)\n",
		      msg,
		      event_code_name(ev->eventCode),
		      ev->eventCode,
		      ev->eventVal,
		      ev->contextID, ev->ctxValid,
		      ev->objID, ev->objValid,
		      ev->objID_2, ev->objValid_2);
}
#endif