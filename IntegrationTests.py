import unittest
import main
import tkinter as tk
import os
import csv
import json


class TestCTI(unittest.TestCase):

    def setUp(self):
        self.app = main.window

    def tearDown(self):
        self.app.update()
        self.app.destroy()

    def test_window_title(self):
        self.assertEqual(self.app.title(), "Select Profile")

    def test_window_size(self):
        self.assertEqual(self.app.geometry(), "550x350")

    def test_label_text(self):
        label = self.app.children['!label']
        self.assertEqual(label.cget('text'), "Welcome to ThreatLink Intelligence")

    def test_buttons_exist(self):
        button_frame = self.app.children['!frame']
        analyst_button = button_frame.children['!button']
        management_button = button_frame.children['!button2']
        csirt_button = button_frame.children['!button3']

        self.assertIsNotNone(analyst_button)
        self.assertIsNotNone(management_button)
        self.assertIsNotNone(csirt_button)

    def test_button_text(self):
        button_frame = self.app.children['!frame']
        analyst_button = button_frame.children['!button']
        management_button = button_frame.children['!button2']
        csirt_button = button_frame.children['!button3']

        self.assertEqual(analyst_button.cget('text'), "Analyst")
        self.assertEqual(management_button.cget('text'), "Management")
        self.assertEqual(csirt_button.cget('text'), "CSIRT")


if __name__ == '__main__':
    unittest.main()
