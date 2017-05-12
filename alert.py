# use standard Python logging
import logging
logging.basicConfig(level=logging.INFO)
import gntp.notifier

growl = gntp.notifier.GrowlNotifier(
 applicationName = "DeDePro",
 notifications = ["New Updates","New Messages"],
 defaultNotifications = ["New Messages"],
 hostname = "192.168.2.100", # Client IP address
 password = "b4ng4u80"# Growl Passwd
)
growl.register()
# Send one message
growl.notify(
 noteType = "New Messages",
 title = "Personal WIDS",
 description = "De-authentication attacks detected",
 icon = "https://www.iconfinder.com/icons/48991/download/png/128", #you can optionally define an image icon to appear with the notification
 sticky = False,
 priority = 1,
)
