from locust import HttpUser, task, between

class DashboardUser(HttpUser):
    wait_time = between(0, 0.1)  # no wait – hammer it

    @task
    def get_root(self):
        self.client.get("/")