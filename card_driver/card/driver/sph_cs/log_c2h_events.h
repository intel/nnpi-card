/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/

#ifndef _NNP_LOG_C2H_EVENTS_H
#define _NNP_LOG_C2H_EVENTS_H

#ifdef _DEBUG
/*
 * debug function to log c2h event report - implemented in
 * common/ipc_c2h_events.c
 */
void log_c2h_event(const char *msg, const union c2h_event_report *ev);
#else
#define log_c2h_event(x, y)
#endif

#endif /* of _NNP_LOG_C2H_EVENTS_H */
