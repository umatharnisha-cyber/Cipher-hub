document.addEventListener('DOMContentLoaded', () => {
  // Initialize Lucide Icons
  lucide.createIcons();

  // Navigation DOM Elements
  const navHomeBtn = document.getElementById('nav-home');
  const navAboutBtn = document.getElementById('nav-about');
  const logoBtn = document.getElementById('logo-btn');
  const toolsDropdown = document.getElementById('tools-dropdown');
  const sections = document.querySelectorAll('.app-section');
  const featureCards = document.querySelectorAll('.feature-card');

  // Review Form elements
  const reviewForm = document.getElementById('about-review-form');

  // Function to switch active section
  function showSection(sectionId) {
    sections.forEach(sec => {
      if (sec.id === `section-${sectionId}`) {
        sec.classList.add('active');
      } else {
        sec.classList.remove('active');
      }
    });

    // Reset navigation active status
    navHomeBtn.classList.remove('active');
    navAboutBtn.classList.remove('active');

    if (sectionId === 'home') {
      navHomeBtn.classList.add('active');
      toolsDropdown.value = ""; // Reset dropdown
    } else if (sectionId === 'about') {
      navAboutBtn.classList.add('active');
      toolsDropdown.value = ""; // Reset dropdown
    } else {
      // Sync dropdown selector
      toolsDropdown.value = sectionId;
    }

    // Scroll to top
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }

  // Navigation Event Listeners
  navHomeBtn.addEventListener('click', (e) => {
    e.preventDefault();
    showSection('home');
  });

  navAboutBtn.addEventListener('click', (e) => {
    e.preventDefault();
    showSection('about');
  });

  logoBtn.addEventListener('click', (e) => {
    e.preventDefault();
    showSection('home');
  });

  // Dropdown navigation trigger
  toolsDropdown.addEventListener('change', (e) => {
    const selectedTool = e.target.value;
    if (selectedTool) {
      showSection(selectedTool);
    }
  });

  // Home card navigation trigger
  featureCards.forEach(card => {
    card.addEventListener('click', () => {
      const toolId = card.getAttribute('data-tool');
      if (toolId) {
        showSection(toolId);
      }
    });
  });

  // Review Form Submission Handler
  if (reviewForm) {
    reviewForm.addEventListener('submit', (e) => {
      e.preventDefault();
      
      const rating = document.getElementById('review-rating').value;
      const comment = document.getElementById('review-comment').value;

      const stars = '★'.repeat(rating) + '☆'.repeat(5 - rating);

      const emailRecipient = 'umatharnisha@gmail.com';
      const emailSubject = encodeURIComponent('Cipher Hub Web App Review - IBM SkillsBuild 2026');
      
      const emailBody = encodeURIComponent(
        `Dear Umat Harnishaba,\n\n` +
        `I have evaluated the Cipher Hub Cybersecurity Application. Here is my feedback:\n\n` +
        `-----------------------------------------\n` +
        `Rating: ${stars} (${rating}/5)\n` +
        `Comments:\n${comment}\n` +
        `-----------------------------------------\n\n` +
        `App Context:\n` +
        `- Developer: Umat Harnishaba (SIR BPTI BHAVNAGAR)\n` +
        `- Guideline: AYUSH KUMAR (CSRBOX)\n` +
        `- Program: IBM SkillsBuild Skill-Based Training Program 2026\n\n` +
        `Best regards,\n` +
        `[My Name]`
      );

      // Open mail client
      window.location.href = `mailto:${emailRecipient}?subject=${emailSubject}&body=${emailBody}`;

      // Reset form
      reviewForm.reset();
    });
  }
});
