/* ==========================================================================
   College Event Management System: front-end behaviour
   Everything here is progressive enhancement. The site still works if this
   file fails to load, because Flask validates every form and filters events too.

   1. Mobile menu            5. Delete / cancel confirmation
   2. Flash messages         6. Star rating
   3. Show / hide password   7. Live event search + filters
   4. Form validation        8. Small helpers (autosubmit, image fallback)
   ========================================================================== */
(function () {
  'use strict';

  var $ = function (selector, root) { return (root || document).querySelector(selector); };
  var $$ = function (selector, root) { return Array.prototype.slice.call((root || document).querySelectorAll(selector)); };

  /* 1. Mobile menu ---------------------------------------------------------- */
  var header = $('.site-header');
  var navToggle = $('#nav-toggle');

  if (header && navToggle) {
    header.classList.add('is-collapsible'); // without JS the menu simply stays visible

    var setMenu = function (open) {
      header.classList.toggle('is-open', open);
      navToggle.setAttribute('aria-expanded', String(open));
      navToggle.setAttribute('aria-label', open ? 'Close menu' : 'Open menu');
    };

    navToggle.addEventListener('click', function () {
      setMenu(!header.classList.contains('is-open'));
    });
    document.addEventListener('keydown', function (event) {
      if (event.key === 'Escape' && header.classList.contains('is-open')) {
        setMenu(false);
        navToggle.focus();
      }
    });
    document.addEventListener('click', function (event) {
      if (header.classList.contains('is-open') && !header.contains(event.target)) { setMenu(false); }
    });
    window.addEventListener('resize', function () {
      if (window.innerWidth > 860) { setMenu(false); }
    });
  }

  /* 2. Flash messages: dismiss button + auto-hide ---------------------------- */
  function hideFlash(flash) {
    if (!flash || flash.classList.contains('is-hiding')) { return; }
    flash.classList.add('is-hiding');
    setTimeout(function () { flash.remove(); }, 450);
  }

  $$('.flash').forEach(function (flash) {
    var closeBtn = $('.flash__close', flash);
    if (closeBtn) { closeBtn.addEventListener('click', function () { hideFlash(flash); }); }
    // Errors stay a little longer so they can be read.
    var delay = flash.classList.contains('flash--error') ? 9000 : 6000;
    setTimeout(function () { hideFlash(flash); }, delay);
  });

  /* 3. Show / hide password -------------------------------------------------- */
  $$('[data-toggle-password]').forEach(function (button) {
    button.addEventListener('click', function () {
      var input = document.getElementById(button.getAttribute('data-toggle-password'));
      if (!input) { return; }
      var show = input.type === 'password';
      input.type = show ? 'text' : 'password';
      button.setAttribute('aria-pressed', String(show));
      button.setAttribute('aria-label', show ? 'Hide password' : 'Show password');
    });
  });

  /* 4. Form validation ------------------------------------------------------- */
  var EMAIL_PATTERN = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
  var URL_PATTERN = /^(https?:\/\/|\/static\/)\S+$/i;

  function setFieldError(field, message) {
    var wrapper = field.closest('.field');
    var errorBox = document.getElementById(field.id + '-error');
    if (errorBox) { errorBox.textContent = message; }
    if (wrapper) { wrapper.classList.toggle('is-invalid', Boolean(message)); }
    if (message) { field.setAttribute('aria-invalid', 'true'); } else { field.removeAttribute('aria-invalid'); }
  }

  function checkField(field) {
    var label = field.getAttribute('data-label') || 'This field';
    var isPassword = field.type === 'password';
    var value = isPassword ? field.value : field.value.trim();
    var message = '';

    if (field.required && !value) {
      message = label + ' is required.';
    } else if (value && field.type === 'email' && !EMAIL_PATTERN.test(value)) {
      message = 'Enter a valid email address.';
    } else if (value && field.minLength > 0 && value.length < field.minLength) {
      message = label + ' must be at least ' + field.minLength + ' characters.';
    } else if (field.hasAttribute('data-match')) {
      var other = document.getElementById(field.getAttribute('data-match'));
      if (other && field.value !== other.value) { message = 'Passwords do not match.'; }
    } else if (value && field.type === 'number') {
      var number = Number(value);
      if (!Number.isInteger(number)) {
        message = label + ' must be a whole number.';
      } else if (field.min !== '' && number < Number(field.min)) {
        message = label + ' must be at least ' + field.min + '.';
      } else if (field.max !== '' && number > Number(field.max)) {
        message = label + ' must be ' + field.max + ' or less.';
      }
    } else if (value && field.hasAttribute('data-url') && !URL_PATTERN.test(value)) {
      message = 'Use a link that starts with http:// or https://.';
    }

    setFieldError(field, message);
    return !message;
  }

  function checkRating(group) {
    var chosen = $('input[type="radio"]:checked', group);
    var errorBox = $('.field__error', group);
    if (errorBox) { errorBox.textContent = chosen ? '' : 'Please select a rating from 1 to 5 stars.'; }
    group.classList.toggle('is-invalid', !chosen);
    return Boolean(chosen);
  }

  $$('form[data-validate]').forEach(function (form) {
    var fields = $$('input, select, textarea', form).filter(function (field) {
      return field.type !== 'hidden' && field.type !== 'radio' && field.type !== 'submit';
    });
    var ratingGroup = $('[data-rating]', form);

    fields.forEach(function (field) {
      field.addEventListener('blur', function () {
        if (field.value !== '' || field.closest('.field').classList.contains('is-invalid')) { checkField(field); }
      });
      var recheck = function () {
        if (field.closest('.field').classList.contains('is-invalid') || field.getAttribute('data-touched')) { checkField(field); }
      };
      field.addEventListener('input', recheck);
      field.addEventListener('change', recheck);
      field.addEventListener('blur', function () { field.setAttribute('data-touched', 'true'); });

      // Keep "confirm password" in step when the first password changes.
      if (field.id && $('[data-match="' + field.id + '"]', form)) {
        field.addEventListener('input', function () {
          var confirmField = $('[data-match="' + field.id + '"]', form);
          if (confirmField.value) { checkField(confirmField); }
        });
      }
    });

    if (ratingGroup) {
      $$('input[type="radio"]', ratingGroup).forEach(function (radio) {
        radio.addEventListener('change', function () { checkRating(ratingGroup); });
      });
    }

    form.addEventListener('submit', function (event) {
      var firstInvalid = null;
      fields.forEach(function (field) {
        if (!checkField(field) && !firstInvalid) { firstInvalid = field; }
      });
      if (ratingGroup && !checkRating(ratingGroup) && !firstInvalid) {
        firstInvalid = $('input[type="radio"]', ratingGroup);
      }
      if (firstInvalid) {
        event.preventDefault();
        firstInvalid.focus();
      }
    });
  });

  /* 5. Confirmation before deleting / cancelling ----------------------------- */
  $$('form[data-confirm]').forEach(function (form) {
    form.addEventListener('submit', function (event) {
      if (!confirm(form.getAttribute('data-confirm'))) { event.preventDefault(); }
    });
  });

  /* 6. Star rating (the radio buttons work on their own; this adds the label) */
  var RATING_WORDS = { 1: 'Poor', 2: 'Fair', 3: 'Good', 4: 'Very good', 5: 'Excellent' };

  $$('[data-rating]').forEach(function (group) {
    var text = $('.rating__text', group);
    var radios = $$('input[type="radio"]', group);
    var labels = $$('label', group);
    if (!text) { return; }

    var currentText = function () {
      var chosen = $('input[type="radio"]:checked', group);
      return chosen ? chosen.value + ' / 5: ' + RATING_WORDS[chosen.value] : 'Select a rating';
    };
    radios.forEach(function (radio) {
      radio.addEventListener('change', function () { text.textContent = currentText(); });
    });
    labels.forEach(function (label) {
      var value = label.getAttribute('for').replace('rating-', '');
      label.addEventListener('mouseenter', function () { text.textContent = value + ' / 5: ' + RATING_WORDS[value]; });
      label.addEventListener('mouseleave', function () { text.textContent = currentText(); });
    });
  });

  /* 7. Live search + category + date filter on the events page --------------- */
  var filterForm = $('#event-filter');

  if (filterForm) {
    var searchInput = $('#filter-q');
    var categorySelect = $('#filter-category');
    var dateInput = $('#filter-date');
    var cards = $$('.event-card');
    var sections = $$('[data-section]');
    var countNumber = $('#results-number');
    var countLabel = $('#results-count');
    var emptyState = $('#no-results');

    var applyFilters = function () {
      var term = searchInput.value.trim().toLowerCase();
      var category = categorySelect.value;
      var date = dateInput.value;
      var visible = 0;

      cards.forEach(function (card) {
        var matches =
          (!term || card.getAttribute('data-search').indexOf(term) !== -1) &&
          (!category || card.getAttribute('data-category') === category) &&
          (!date || card.getAttribute('data-date') === date);
        card.hidden = !matches;
        if (matches) { visible += 1; }
      });

      sections.forEach(function (section) {
        var shown = $$('.event-card', section).filter(function (card) { return !card.hidden; }).length;
        section.hidden = shown === 0;
        var badge = $('.event-section__title span', section);
        if (badge) { badge.textContent = shown; }
      });

      countNumber.textContent = visible;
      countLabel.lastChild.textContent = ' event' + (visible === 1 ? '' : 's') + ' found';
      emptyState.hidden = visible !== 0;

      // Keep the address bar shareable without reloading the page.
      var params = new URLSearchParams();
      if (term) { params.set('q', searchInput.value.trim()); }
      if (category) { params.set('category', category); }
      if (date) { params.set('date', date); }
      var query = params.toString();
      history.replaceState(null, '', window.location.pathname + (query ? '?' + query : ''));
    };

    filterForm.addEventListener('input', applyFilters);
    filterForm.addEventListener('change', applyFilters);
    filterForm.addEventListener('submit', function (event) { event.preventDefault(); applyFilters(); });
    $('#filter-reset').addEventListener('click', function (event) {
      event.preventDefault();
      filterForm.reset();
      searchInput.value = '';
      categorySelect.value = '';
      dateInput.value = '';
      applyFilters();
      searchInput.focus();
    });
    applyFilters();
  }

  /* 8. Small helpers --------------------------------------------------------- */
  // Selects marked data-autosubmit submit their form when changed.
  $$('select[data-autosubmit]').forEach(function (select) {
    select.addEventListener('change', function () { select.form.submit(); });
  });

  // If an event image URL is broken, fall back to the coloured cover.
  function useColourCover(img) {
    var cover = img.parentElement;
    img.remove();
    if (cover) { cover.classList.remove('has-image'); }
  }
  document.addEventListener('error', function (event) {
    if (event.target.tagName === 'IMG' && event.target.classList.contains('event-card__img')) {
      useColourCover(event.target);
    }
  }, true);
  $$('img.event-card__img').forEach(function (img) {
    if (img.complete && img.naturalWidth === 0) { useColourCover(img); }
  });
})();
