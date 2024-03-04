/* ###
 * IP: Apache License 2.0 with LLVM Exceptions
 */
/* ----------------------------------------------------------------------------
 * This file was automatically generated by SWIG (http://www.swig.org).
 * Version 4.0.1
 *
 * Do not make changes to this file unless you know what you are doing--modify
 * the SWIG interface file instead.
 * ----------------------------------------------------------------------------- */

package SWIG;

public class SBThread {
  private transient long swigCPtr;
  protected transient boolean swigCMemOwn;

  protected SBThread(long cPtr, boolean cMemoryOwn) {
    swigCMemOwn = cMemoryOwn;
    swigCPtr = cPtr;
  }

  protected static long getCPtr(SBThread obj) {
    return (obj == null) ? 0 : obj.swigCPtr;
  }

  @SuppressWarnings("deprecation")
  protected void finalize() {
    delete();
  }

  public synchronized void delete() {
    if (swigCPtr != 0) {
      if (swigCMemOwn) {
        swigCMemOwn = false;
        lldbJNI.delete_SBThread(swigCPtr);
      }
      swigCPtr = 0;
    }
  }

  public SBThread() {
    this(lldbJNI.new_SBThread__SWIG_0(), true);
  }

  public SBThread(SBThread thread) {
    this(lldbJNI.new_SBThread__SWIG_1(SBThread.getCPtr(thread), thread), true);
  }

  public static String GetBroadcasterClassName() {
    return lldbJNI.SBThread_GetBroadcasterClassName();
  }

  public static boolean EventIsThreadEvent(SBEvent event) {
    return lldbJNI.SBThread_EventIsThreadEvent(SBEvent.getCPtr(event), event);
  }

  public static SBFrame GetStackFrameFromEvent(SBEvent event) {
    return new SBFrame(lldbJNI.SBThread_GetStackFrameFromEvent(SBEvent.getCPtr(event), event), true);
  }

  public static SBThread GetThreadFromEvent(SBEvent event) {
    return new SBThread(lldbJNI.SBThread_GetThreadFromEvent(SBEvent.getCPtr(event), event), true);
  }

  public boolean IsValid() {
    return lldbJNI.SBThread_IsValid(swigCPtr, this);
  }

  public void Clear() {
    lldbJNI.SBThread_Clear(swigCPtr, this);
  }

  public StopReason GetStopReason() {
    return StopReason.swigToEnum(lldbJNI.SBThread_GetStopReason(swigCPtr, this));
  }

  public long GetStopReasonDataCount() {
    return lldbJNI.SBThread_GetStopReasonDataCount(swigCPtr, this);
  }

  public java.math.BigInteger GetStopReasonDataAtIndex(long idx) {
    return lldbJNI.SBThread_GetStopReasonDataAtIndex(swigCPtr, this, idx);
  }

  public boolean GetStopReasonExtendedInfoAsJSON(SBStream stream) {
    return lldbJNI.SBThread_GetStopReasonExtendedInfoAsJSON(swigCPtr, this, SBStream.getCPtr(stream), stream);
  }

  public SBThreadCollection GetStopReasonExtendedBacktraces(InstrumentationRuntimeType type) {
    return new SBThreadCollection(lldbJNI.SBThread_GetStopReasonExtendedBacktraces(swigCPtr, this, type.swigValue()), true);
  }

  public long GetStopDescription(String dst_or_null, long dst_len) {
    return lldbJNI.SBThread_GetStopDescription(swigCPtr, this, dst_or_null, dst_len);
  }

  public SBValue GetStopReturnValue() {
    return new SBValue(lldbJNI.SBThread_GetStopReturnValue(swigCPtr, this), true);
  }

  public java.math.BigInteger GetThreadID() {
    return lldbJNI.SBThread_GetThreadID(swigCPtr, this);
  }

  public long GetIndexID() {
    return lldbJNI.SBThread_GetIndexID(swigCPtr, this);
  }

  public String GetName() {
    return lldbJNI.SBThread_GetName(swigCPtr, this);
  }

  public String GetQueueName() {
    return lldbJNI.SBThread_GetQueueName(swigCPtr, this);
  }

  public java.math.BigInteger GetQueueID() {
    return lldbJNI.SBThread_GetQueueID(swigCPtr, this);
  }

  public boolean GetInfoItemByPathAsString(String path, SBStream strm) {
    return lldbJNI.SBThread_GetInfoItemByPathAsString(swigCPtr, this, path, SBStream.getCPtr(strm), strm);
  }

  public SBQueue GetQueue() {
    return new SBQueue(lldbJNI.SBThread_GetQueue(swigCPtr, this), true);
  }

  public void StepOver(RunMode stop_other_threads) {
    lldbJNI.SBThread_StepOver__SWIG_0(swigCPtr, this, stop_other_threads.swigValue());
  }

  public void StepOver() {
    lldbJNI.SBThread_StepOver__SWIG_1(swigCPtr, this);
  }

  public void StepOver(RunMode stop_other_threads, SBError error) {
    lldbJNI.SBThread_StepOver__SWIG_2(swigCPtr, this, stop_other_threads.swigValue(), SBError.getCPtr(error), error);
  }

  public void StepInto(RunMode stop_other_threads) {
    lldbJNI.SBThread_StepInto__SWIG_0(swigCPtr, this, stop_other_threads.swigValue());
  }

  public void StepInto() {
    lldbJNI.SBThread_StepInto__SWIG_1(swigCPtr, this);
  }

  public void StepInto(String target_name, RunMode stop_other_threads) {
    lldbJNI.SBThread_StepInto__SWIG_2(swigCPtr, this, target_name, stop_other_threads.swigValue());
  }

  public void StepInto(String target_name) {
    lldbJNI.SBThread_StepInto__SWIG_3(swigCPtr, this, target_name);
  }

  public void StepInto(String target_name, long end_line, SBError error, RunMode stop_other_threads) {
    lldbJNI.SBThread_StepInto__SWIG_4(swigCPtr, this, target_name, end_line, SBError.getCPtr(error), error, stop_other_threads.swigValue());
  }

  public void StepInto(String target_name, long end_line, SBError error) {
    lldbJNI.SBThread_StepInto__SWIG_5(swigCPtr, this, target_name, end_line, SBError.getCPtr(error), error);
  }

  public void StepOut() {
    lldbJNI.SBThread_StepOut__SWIG_0(swigCPtr, this);
  }

  public void StepOut(SBError error) {
    lldbJNI.SBThread_StepOut__SWIG_1(swigCPtr, this, SBError.getCPtr(error), error);
  }

  public void StepOutOfFrame(SBFrame frame) {
    lldbJNI.SBThread_StepOutOfFrame__SWIG_0(swigCPtr, this, SBFrame.getCPtr(frame), frame);
  }

  public void StepOutOfFrame(SBFrame frame, SBError error) {
    lldbJNI.SBThread_StepOutOfFrame__SWIG_1(swigCPtr, this, SBFrame.getCPtr(frame), frame, SBError.getCPtr(error), error);
  }

  public void StepInstruction(boolean step_over) {
    lldbJNI.SBThread_StepInstruction__SWIG_0(swigCPtr, this, step_over);
  }

  public void StepInstruction(boolean step_over, SBError error) {
    lldbJNI.SBThread_StepInstruction__SWIG_1(swigCPtr, this, step_over, SBError.getCPtr(error), error);
  }

  public SBError StepOverUntil(SBFrame frame, SBFileSpec file_spec, long line) {
    return new SBError(lldbJNI.SBThread_StepOverUntil(swigCPtr, this, SBFrame.getCPtr(frame), frame, SBFileSpec.getCPtr(file_spec), file_spec, line), true);
  }

  public SBError StepUsingScriptedThreadPlan(String script_class_name) {
    return new SBError(lldbJNI.SBThread_StepUsingScriptedThreadPlan__SWIG_0(swigCPtr, this, script_class_name), true);
  }

  public SBError StepUsingScriptedThreadPlan(String script_class_name, boolean resume_immediately) {
    return new SBError(lldbJNI.SBThread_StepUsingScriptedThreadPlan__SWIG_1(swigCPtr, this, script_class_name, resume_immediately), true);
  }

  public SBError StepUsingScriptedThreadPlan(String script_class_name, SBStructuredData args_data, boolean resume_immediately) {
    return new SBError(lldbJNI.SBThread_StepUsingScriptedThreadPlan__SWIG_2(swigCPtr, this, script_class_name, SBStructuredData.getCPtr(args_data), args_data, resume_immediately), true);
  }

  public SBError JumpToLine(SBFileSpec file_spec, long line) {
    return new SBError(lldbJNI.SBThread_JumpToLine(swigCPtr, this, SBFileSpec.getCPtr(file_spec), file_spec, line), true);
  }

  public void RunToAddress(java.math.BigInteger addr) {
    lldbJNI.SBThread_RunToAddress__SWIG_0(swigCPtr, this, addr);
  }

  public void RunToAddress(java.math.BigInteger addr, SBError error) {
    lldbJNI.SBThread_RunToAddress__SWIG_1(swigCPtr, this, addr, SBError.getCPtr(error), error);
  }

  public SBError ReturnFromFrame(SBFrame frame, SBValue return_value) {
    return new SBError(lldbJNI.SBThread_ReturnFromFrame(swigCPtr, this, SBFrame.getCPtr(frame), frame, SBValue.getCPtr(return_value), return_value), true);
  }

  public SBError UnwindInnermostExpression() {
    return new SBError(lldbJNI.SBThread_UnwindInnermostExpression(swigCPtr, this), true);
  }

  public boolean Suspend() {
    return lldbJNI.SBThread_Suspend__SWIG_0(swigCPtr, this);
  }

  public boolean Suspend(SBError error) {
    return lldbJNI.SBThread_Suspend__SWIG_1(swigCPtr, this, SBError.getCPtr(error), error);
  }

  public boolean Resume() {
    return lldbJNI.SBThread_Resume__SWIG_0(swigCPtr, this);
  }

  public boolean Resume(SBError error) {
    return lldbJNI.SBThread_Resume__SWIG_1(swigCPtr, this, SBError.getCPtr(error), error);
  }

  public boolean IsSuspended() {
    return lldbJNI.SBThread_IsSuspended(swigCPtr, this);
  }

  public boolean IsStopped() {
    return lldbJNI.SBThread_IsStopped(swigCPtr, this);
  }

  public long GetNumFrames() {
    return lldbJNI.SBThread_GetNumFrames(swigCPtr, this);
  }

  public SBFrame GetFrameAtIndex(long idx) {
    return new SBFrame(lldbJNI.SBThread_GetFrameAtIndex(swigCPtr, this, idx), true);
  }

  public SBFrame GetSelectedFrame() {
    return new SBFrame(lldbJNI.SBThread_GetSelectedFrame(swigCPtr, this), true);
  }

  public SBFrame SetSelectedFrame(long frame_idx) {
    return new SBFrame(lldbJNI.SBThread_SetSelectedFrame(swigCPtr, this, frame_idx), true);
  }

  public SBProcess GetProcess() {
    return new SBProcess(lldbJNI.SBThread_GetProcess(swigCPtr, this), true);
  }

  public boolean GetDescription(SBStream description) {
    return lldbJNI.SBThread_GetDescription__SWIG_0(swigCPtr, this, SBStream.getCPtr(description), description);
  }

  public boolean GetDescription(SBStream description, boolean stop_format) {
    return lldbJNI.SBThread_GetDescription__SWIG_1(swigCPtr, this, SBStream.getCPtr(description), description, stop_format);
  }

  public boolean GetStatus(SBStream status) {
    return lldbJNI.SBThread_GetStatus(swigCPtr, this, SBStream.getCPtr(status), status);
  }

  public SBThread GetExtendedBacktraceThread(String type) {
    return new SBThread(lldbJNI.SBThread_GetExtendedBacktraceThread(swigCPtr, this, type), true);
  }

  public long GetExtendedBacktraceOriginatingIndexID() {
    return lldbJNI.SBThread_GetExtendedBacktraceOriginatingIndexID(swigCPtr, this);
  }

  public SBValue GetCurrentException() {
    return new SBValue(lldbJNI.SBThread_GetCurrentException(swigCPtr, this), true);
  }

  public SBThread GetCurrentExceptionBacktrace() {
    return new SBThread(lldbJNI.SBThread_GetCurrentExceptionBacktrace(swigCPtr, this), true);
  }

  public boolean SafeToCallFunctions() {
    return lldbJNI.SBThread_SafeToCallFunctions(swigCPtr, this);
  }

  public SBValue GetSiginfo() {
    return new SBValue(lldbJNI.SBThread_GetSiginfo(swigCPtr, this), true);
  }

  public String __repr__() {
    return lldbJNI.SBThread___repr__(swigCPtr, this);
  }

  public final static int eBroadcastBitStackChanged = lldbJNI.SBThread_eBroadcastBitStackChanged_get();
  public final static int eBroadcastBitThreadSuspended = lldbJNI.SBThread_eBroadcastBitThreadSuspended_get();
  public final static int eBroadcastBitThreadResumed = lldbJNI.SBThread_eBroadcastBitThreadResumed_get();
  public final static int eBroadcastBitSelectedFrameChanged = lldbJNI.SBThread_eBroadcastBitSelectedFrameChanged_get();
  public final static int eBroadcastBitThreadSelected = lldbJNI.SBThread_eBroadcastBitThreadSelected_get();

}
