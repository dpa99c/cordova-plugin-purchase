package cc.fovea;

import android.util.Log;
import org.apache.cordova.CallbackContext;
import org.apache.cordova.PluginResult;
import org.json.JSONException;
import org.json.JSONObject;

/** Centralised native logger for the purchase plugin. */
public final class Logger {

  /** Native log severity. */
  public enum Level {
    DEBUG,
    INFO,
    WARNING,
    ERROR
  }

  private static CallbackContext sCallbackContext;

  private final String mTag;

  /** Create a logger with the supplied native log tag. */
  public Logger(final String tag) {
    mTag = tag;
  }

  /** Register or replace the JavaScript log callback. */
  public static synchronized void registerCallback(final CallbackContext callbackContext) {
    sCallbackContext = callbackContext;
    send(Level.INFO, "Native log listener registered");
  }

  /** Clear the JavaScript log callback. */
  public static synchronized void clearCallback() {
    sCallbackContext = null;
  }

  /** Emit a debug message. */
  public void debug(final String tag, final String message) {
    emit(Level.DEBUG, message);
  }

  /** Emit an informational message. */
  public void info(final String tag, final String message) {
    emit(Level.INFO, message);
  }

  /** Emit a warning message. */
  public void warning(final String tag, final String message) {
    emit(Level.WARNING, message);
  }

  /** Emit an error message. */
  public void error(final String tag, final String message) {
    emit(Level.ERROR, message);
  }

  private void emit(final Level level, final String message) {
    final String formattedMessage = "[CdvPurchase.GooglePlay] " + message;
    switch (level) {
      case ERROR:
        Log.e(mTag, formattedMessage);
        break;
      case WARNING:
        Log.w(mTag, formattedMessage);
        break;
      case INFO:
        Log.i(mTag, formattedMessage);
        break;
      case DEBUG:
      default:
        Log.d(mTag, formattedMessage);
        break;
    }
    send(level, formattedMessage);
  }

  private static synchronized void send(final Level level, final String message) {
    if (sCallbackContext == null) {
      return;
    }
    try {
      final String levelName;
      switch (level) {
        case ERROR:
          levelName = "error";
          break;
        case WARNING:
          levelName = "warning";
          break;
        case INFO:
          levelName = "info";
          break;
        case DEBUG:
        default:
          levelName = "debug";
          break;
      }
      final JSONObject payload = new JSONObject()
          .put("level", levelName)
          .put("message", message);
      final PluginResult result = new PluginResult(PluginResult.Status.OK, payload);
      result.setKeepCallback(true);
      sCallbackContext.sendPluginResult(result);
    } catch (JSONException exception) {
      Log.e("CdvPurchase", "Unable to send native log message", exception);
    }
  }
}
