# AIDEX Base Template Design

## Introduction

The Base Template is the main layout used throughout the AIDEX system. Every page extends this template to maintain a consistent user interface and user experience.

---

## Objectives

The primary objectives of the Base Template are:

- Maintain a consistent UI
- Reduce duplicate code
- Improve maintainability
- Provide responsive layouts
- Integrate Bootstrap 5

---

## Main Components

The Base Template contains:

- Navigation Bar
- Main Content Area
- Footer
- Bootstrap CSS
- Bootstrap JavaScript
- Bootstrap Icons
- Django Messages
- Custom CSS
- Template Blocks

---

## Navigation Bar

The Navigation Bar includes:

- AIDEX Logo
- Dashboard
- Profile
- Login
- Register
- Logout

The navigation items change dynamically based on user authentication status.

---

## Main Content

The content section uses Django Template Blocks.

Example:

{% block content %}

{% endblock %}

Every page extends the Base Template and injects page-specific content.

---

## Responsive Design

The template is fully responsive using Bootstrap Grid System.

Supported Devices:

- Desktop
- Laptop
- Tablet
- Mobile

---

## Technologies Used

- HTML5
- CSS3
- Bootstrap 5
- Django Template Engine
- Bootstrap Icons

---

## Expected Result

The Base Template provides a professional, reusable and responsive layout for all pages within the AIDEX system.