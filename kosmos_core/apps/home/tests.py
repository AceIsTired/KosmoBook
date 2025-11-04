from django.test import TestCase, Client
from django.urls import reverse
import time

# losts of these tests check the home page for the correct response and assumed behavior. basically content and correctness tests

class home_tests(TestCase):
    def start(self):
        self.client = Client()  # makes a test client

    def test_running(self):
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)

    def test_url_name(self):
        response = self.client.get(reverse('home:home'))
        self.assertEqual(response.status_code, 200)

    def test_has_sitename(self):
        response = self.client.get('/')
        self.assertContains(response, 'Kosmobook')

    def test_html(self):
        response = self.client.get('/')
        self.assertTemplateUsed(response, 'home/home.html') # correct html file

    def test_html2(self):
        response = self.client.get('/')
        self.assertTrue(response.content.startswith(b'<!DOCTYPE html>')) # correct doctype

    def test_html3(self):
        response = self.client.get('/')
        self.assertEqual(response['content-type'], 'text/html; charset=utf-8') # correct content type

    def test_has_test_message(self):
        response = self.client.get('/')
        self.assertContains(response, 'You made it to the homepage!')

    def test_error(self):
        response = self.client.get('/')
        self.assertNotContains(response, '404')
        self.assertNotContains(response, 'Not Found')

    def test_multi_visit(self):
        for i in range(5):  # crash test
            response = self.client.get('/')
            self.assertEqual(response.status_code, 200)

    def test_load_speed(self): # i found this kind of test online
        start_time = time.time()
        response = self.client.get('/')
        end_time = time.time()

        load_time = end_time - start_time
        self.assertEqual(response.status_code, 200)
        self.assertLess(load_time, 1.0,f"Page loaded in {load_time} seconds")
