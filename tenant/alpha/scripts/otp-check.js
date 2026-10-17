// Ask for a one-time code, then compare it with the ESV that stands in for the real second factor.
if (callbacks.isEmpty()) {
  callbacksBuilder.textInputCallback("One-time code");
} else {
  var code = String(callbacks.getTextInputCallbacks().get(0));
  action.goTo(code === systemEnv.getProperty("esv.demo.otp") ? "true" : "false");
}
