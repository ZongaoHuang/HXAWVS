#!/usr/bin/env python
# -*- coding: utf-8 -*-

from tkinter import Image
from .Base import Base
import requests
import PyPDF2
from io import BytesIO
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from PyPDF2 import PdfReader, PdfWriter
import io
from PIL import Image
from reportlab.lib.utils import ImageReader
import fitz
class Report(Base):
    def __init__(self, api_base_url, api_key):
        super().__init__(api_base_url, api_key)
        self.logger = self.get_logger

    def get_all(self):
        try:
            response = requests.get(self.report_api, headers=self.auth_headers, verify=False)
            return response.json()
        except Exception:
            self.logger.error('Get All Reports Failed......', exc_info=True)
            return None

    def generate(self, template_id, list_type, id_list):
        data = {
            'template_id': self.report_template_dict.get(template_id),
            'source': {
                'list_type': list_type,
                'id_list': id_list
            }
        }
        print(data)
        try:
            response = requests.post(self.report_api, json=data, headers=self.auth_headers, verify=False)
            return True
        except Exception:
            self.logger.error('Generate Report Failed......', exc_info=True)
            return False

    def delete(self, report_id):
        try:
            response = requests.delete(f'{self.report_api}/{report_id}', headers=self.auth_headers, verify=False)
            return True
        except Exception:
            self.logger.error('Delete Report Failed......', exc_info=True)
            return False
        
    def get_modified_report(self, report_id):
        try:
            # First, get the report details to obtain the download descriptor
            response = requests.get(f'{self.report_api}/{report_id}', headers=self.auth_headers, verify=False)
            response.raise_for_status()
            report_details = response.json()
            
            # Get the download descriptor for the PDF
            pdf_descriptor = next((download for download in report_details.get('download', []) if download.endswith('.pdf')), None)
            
            if not pdf_descriptor:
                self.logger.error(f'No PDF download descriptor found for report {report_id}')
                return None
            
            # Download the PDF using the correct endpoint
            response = requests.get(f'{self.api_base_url}{pdf_descriptor}', headers=self.auth_headers, verify=False)
            response.raise_for_status()
            pdf_content = io.BytesIO(response.content)
            
            pdf_reader = PdfReader(pdf_content)
            pdf_writer = PdfWriter()

            # Modify the first page
            first_page = pdf_reader.pages[0]
            modified_first_page = self.modify_first_page(first_page)
            pdf_writer.add_page(modified_first_page)

            # Add remaining pages unchanged
            for page in pdf_reader.pages[1:]:
                pdf_writer.add_page(page)

            output = io.BytesIO()
            pdf_writer.write(output)
            output.seek(0)
            return output.getvalue()
        except requests.RequestException as e:
            self.logger.error(f'Failed to download report {report_id}: {str(e)}')
        except PyPDF2.errors.PdfReadError as e:
            self.logger.error(f'Failed to read PDF for report {report_id}: {str(e)}')
        except Exception as e:
            self.logger.error(f'Unexpected error in get_modified_report for {report_id}: {str(e)}')
        return None
        
    def modify_first_page(self, original_page):
        try:
            # Convert PyPDF2 page to fitz page
            pdf_bytes = io.BytesIO()
            writer = PdfWriter()
            writer.add_page(original_page)
            writer.write(pdf_bytes)
            pdf_bytes.seek(0)
            
            doc = fitz.open("pdf", pdf_bytes)
            page = doc[0]

            # Define the rectangle to cover the top part of the page
            rect = fitz.Rect(0, -50, page.rect.width, 100)

            # Draw a white rectangle to cover the top part of the page
            page.draw_rect(rect, color=(1, 1, 1), fill=True)

            # Search for "Acunetix" instances and cover them
            text_instances = page.search_for("Acunetix")
            for inst in text_instances:
                page.draw_rect(inst, color=(1, 1, 1), fill=True)

            # Save the modified page
            modified_pdf_bytes = io.BytesIO()
            doc.save(modified_pdf_bytes)
            modified_pdf_bytes.seek(0)

            # Convert back to PyPDF2 page
            reader = PdfReader(modified_pdf_bytes)
            return reader.pages[0]
        except Exception as e:
            self.logger.error(f'Failed to modify first page: {str(e)}')
            return original_page