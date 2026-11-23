using System;

namespace CsirtTriage.Core.Uac
{
    /// <summary>
    /// GroupedEvent is used to track:
    /// - how many times an event type occurred
    /// - first seen timestamp
    /// - last seen timestamp
    /// Used in: AuditLogParser, MessagesLogParser, WebLogParser, CronLogParser, etc.
    /// </summary>
    public class GroupedEvent
    {
        public int Count = 0;
        public DateTime FirstSeen = DateTime.MaxValue;
        public DateTime LastSeen = DateTime.MinValue;
    }
}
