#ifndef WPAMSG_H
#define WPAMSG_H

#include <qdatetime.h>

class WpaMsg {
public:
    WpaMsg() {}
    WpaMsg(const QString &_msg, int _priority = 2)
	: msg(_msg), priority(_priority)
    {
	timestamp = QDateTime::currentDateTime();
    }
    
    QString getMsg() const { return msg; }
    int getPriority() const { return priority; }
    QDateTime getTimestamp() const { return timestamp; }
    
private:
    QString msg;
    int priority;
    QDateTime timestamp;
};

typedef QValueList<WpaMsg> WpaMsgList;

#endif /* WPAMSG_H */
