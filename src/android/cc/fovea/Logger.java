package cc.fovea;

import android.util.Log;
import android.os.Handler;
import android.os.Looper;
import org.apache.cordova.CallbackContext;
import org.apache.cordova.PluginResult;
import org.json.JSONException;
import org.json.JSONObject;
import java.util.ArrayList;
import java.util.List;

/** Centralised native logger for the purchase plugin. */
public final class Logger {

  /** Native log severity. */
  public enum Level {
    DEBUG,
    INFO,
    WARNING,
    ERROR
  }

  /** Time allowed for the JavaScript log callback to register. */
  private static final long NATIVE_LOG_CALLBACK_TIMEOUT_MS = 10_000L;

  /** Main-thread scheduler used to expire the startup log buffer. */
  private static final Handler CALLBACK_TIMEOUT_HANDLER = new Handler(Looper.getMainLooper());

  /** Messages emitted before the JavaScript callback is registered. */
  private static final List<BufferedMessage> BUFFERED_MESSAGES = new ArrayList<BufferedMessage>();

  /** Whether startup messages should still be retained. */
  private static boolean sBufferingEnabled = true;

  private static CallbackContext sCallbackContext;

  /** Logger instance used for the startup-buffer expiry warning. */
  private static final Logger TIMEOUT_LOGGER = new Logger("CdvPurchase");

  private static final Runnable CALLBACK_TIMEOUT = new Runnable() {
    @Override
    public void run() {
      expireBufferedMessages();
    }
  };

  static {
    CALLBACK_TIMEOUT_HANDLER.postDelayed(CALLBACK_TIMEOUT, NATIVE_LOG_CALLBACK_TIMEOUT_MS);
  }

  private final String mTag;

  /** A buffered native log payload awaiting callback registration. */
  private static final class BufferedMessage {
    private final Level level;
    private final String message;

    BufferedMessage(final Level level, final String message) {
      this.level = level;
      this.message = message;
    }
  }

  /** Create a logger with the supplied native log tag. */
  public Logger(final String tag) {
    mTag = tag;
  }

  /** Register or replace the JavaScript log callback. */
  public static synchronized void registerCallback(final CallbackContext callbackContext) {
    if (callbackContext == null) {
      return;
    }
    sCallbackContext = callbackContext;
    if (sBufferingEnabled) {
      sBufferingEnabled = false;
      CALLBACK_TIMEOUT_HANDLER.removeCallbacks(CALLBACK_TIMEOUT);
      final List<BufferedMessage> bufferedMessages = new ArrayList<BufferedMessage>(BUFFERED_MESSAGES);
      BUFFERED_MESSAGES.clear();
      for (BufferedMessage bufferedMessage : bufferedMessages) {
        send(bufferedMessage.level, bufferedMessage.message);
      }
    }
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
      if (sBufferingEnabled) {
        BUFFERED_MESSAGES.add(new BufferedMessage(level, message));
      }
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

  private static void expireBufferedMessages() {
    synchronized (Logger.class) {
      if (!sBufferingEnabled) {
        return;
      }
      sBufferingEnabled = false;
      BUFFERED_MESSAGES.clear();
    }
    TIMEOUT_LOGGER.warning("CdvPurchase", "Native log listener was not registered within "
        + (NATIVE_LOG_CALLBACK_TIMEOUT_MS / 1000L)
        + " seconds; buffered messages were discarded");
  }
}
