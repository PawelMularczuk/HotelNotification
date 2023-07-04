
class PriorityType:
    def __init__(self, code, description, selected):
        self.code = code
        self.description = description
        self.selected = selected


class NotificationPriority:
    def __init__(self):
        self.list_of_priorites = []

    def load_priorities(self):
        self.list_of_priorites.append(
            PriorityType('High', 'HIGH PRIORITY', False))
        self.list_of_priorites.append(
            PriorityType('Medium', 'MEDIUM PRIORITY', False))
        self.list_of_priorites.append(
            PriorityType('Normal', 'NOT URGENT', True))
        self.list_of_priorites.append(PriorityType('Low', 'REMARK', False))

    def get_priority_by_code(self, code):
        for priority in self.list_of_priorites:
            if priority.code == code:
                return priority
        return PriorityType('Normal', 'NOT URGENT', True)
