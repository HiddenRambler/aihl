LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE    := aihl
LOCAL_SRC_FILES := aihl.c
LOCAL_CFLAGS    := -std=c99 -Wall
LOCAL_ARM_MODE  := arm

include $(BUILD_STATIC_LIBRARY)
