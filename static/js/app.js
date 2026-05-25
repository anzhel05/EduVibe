// Global UI helpers: nav active state, mobile nav, and course live-search.
(function () {
    var path = window.location.pathname;
    var links = document.querySelectorAll(".nav-link");
    for (var i = 0; i < links.length; i++) {
        var route = links[i].getAttribute("data-route");
        if (route === "/" ? path === "/" : path.indexOf(route) === 0) {
            links[i].classList.add("active");
        }
    }

    var toggle = document.getElementById("menuToggle");
    var nav = document.querySelector(".nav-links");
    if (toggle && nav) {
        toggle.addEventListener("click", function () {
            nav.classList.toggle("open");
        });
    }

    var searchInput = document.getElementById("courseSearchInput");
    var courseGrid = document.getElementById("courseGrid");
    var emptyState = document.getElementById("courseEmptyState");
    if (searchInput && courseGrid) {
        var cards = courseGrid.querySelectorAll(".course-card");

        var runFilter = function () {
            var query = (searchInput.value || "").toLowerCase().trim();
            var visible = 0;
            for (var j = 0; j < cards.length; j++) {
                var haystack = cards[j].getAttribute("data-search") || "";
                var match = !query || haystack.indexOf(query) !== -1;
                cards[j].style.display = match ? "" : "none";
                if (match) {
                    visible += 1;
                }
            }
            if (emptyState) {
                emptyState.style.display = visible === 0 ? "block" : "none";
            }
        };

        searchInput.addEventListener("input", runFilter);
        runFilter();
    }


    var selectedCount = function (checks) {
        var count = 0;
        for (var i = 0; i < checks.length; i++) {
            if (checks[i].checked) {
                count += 1;
            }
        }
        return count;
    };

    var bindCheckList = function (selectAll, checks, updateState) {
        selectAll.addEventListener("change", function () {
            for (var i = 0; i < checks.length; i++) {
                checks[i].checked = selectAll.checked;
            }
            updateState();
        });

        for (var j = 0; j < checks.length; j++) {
            checks[j].addEventListener("change", updateState);
        }
    };

    var setupCourseBulkActions = function () {
        var selectAll = document.getElementById("courseSelectAll");
        var checks = document.querySelectorAll(".course-select-checkbox");
        var action = document.getElementById("coursesBulkAction");
        var applyBtn = document.getElementById("coursesBulkApply");
        var countEl = document.getElementById("courseSelectedCount");

        if (!selectAll || !checks.length || !action || !applyBtn || !countEl) {
            return;
        }

        var updateState = function () {
            var checked = selectedCount(checks);
            countEl.textContent = checked + " selected";
            applyBtn.disabled = !(checked > 0 && action.value);
            selectAll.checked = checked === checks.length;
            selectAll.indeterminate = checked > 0 && checked < checks.length;
        };

        bindCheckList(selectAll, checks, updateState);
        action.addEventListener("change", updateState);
        updateState();
    };

    var setupUserBulkActions = function () {
        var selectAll = document.getElementById("userSelectAll");
        var checks = document.querySelectorAll(".user-select-checkbox");
        var action = document.getElementById("usersBulkAction");
        var applyBtn = document.getElementById("usersBulkApply");
        var countEl = document.getElementById("userSelectedCount");
        var roleEl = document.getElementById("usersBulkRole");
        var statusEl = document.getElementById("usersBulkStatus");

        if (!selectAll || !checks.length || !action || !applyBtn || !countEl) {
            return;
        }

        var updateState = function () {
            var checked = selectedCount(checks);
            var needsRole = action.value === "set_role";
            var needsStatus = action.value === "set_status";
            var actionOk = !!action.value;

            if (roleEl) {
                roleEl.hidden = !needsRole;
                actionOk = needsRole ? actionOk && !!roleEl.value : actionOk;
            }
            if (statusEl) {
                statusEl.hidden = !needsStatus;
                actionOk = needsStatus ? actionOk && !!statusEl.value : actionOk;
            }

            countEl.textContent = checked + " selected";
            applyBtn.disabled = !(checked > 0 && actionOk);
            selectAll.checked = checked === checks.length;
            selectAll.indeterminate = checked > 0 && checked < checks.length;
        };

        bindCheckList(selectAll, checks, updateState);
        action.addEventListener("change", updateState);
        if (roleEl) {
            roleEl.addEventListener("change", updateState);
        }
        if (statusEl) {
            statusEl.addEventListener("change", updateState);
        }
        updateState();
    };

    setupCourseBulkActions();
    setupUserBulkActions();

    var bindRetake = function (form) {
        var retakeBtn = form.querySelector("[data-quiz-retake]");
        if (!retakeBtn) {
            return;
        }
        retakeBtn.addEventListener("click", function () {
            var checkedInputs = form.querySelectorAll("input[type='radio']:checked");
            for (var i = 0; i < checkedInputs.length; i++) {
                checkedInputs[i].checked = false;
            }
            var feedbackNodes = form.querySelectorAll(".quiz-feedback");
            for (var j = 0; j < feedbackNodes.length; j++) {
                feedbackNodes[j].hidden = true;
                feedbackNodes[j].textContent = "";
            }
            var summary = form.querySelector(".quiz-summary");
            if (summary) {
                summary.hidden = true;
                summary.textContent = "";
            }
        });
    };

    var quizForms = document.querySelectorAll(".lesson-quiz-form");
    for (var qf = 0; qf < quizForms.length; qf++) {
        bindRetake(quizForms[qf]);
        quizForms[qf].addEventListener("submit", function (event) {
            event.preventDefault();
            var questions = this.querySelectorAll(".lesson-quiz-question");
            var totalQuestions = 0;
            var score = 0;
            var answers = {};
            for (var qi = 0; qi < questions.length; qi++) {
                var question = questions[qi];
                var answer = (question.getAttribute("data-answer") || "").trim();
                var explanation = question.getAttribute("data-explanation") || "";
                var checked = question.querySelector("input[type='radio']:checked");
                var feedback = question.querySelector(".quiz-feedback");
                totalQuestions += 1;
                if (!feedback) {
                    continue;
                }
                if (!checked) {
                    feedback.hidden = false;
                    feedback.textContent = "Choose one option to check this question.";
                    answers[String(qi)] = "";
                    continue;
                }
                answers[String(qi)] = checked.value;
                if (checked.value === answer) {
                    feedback.hidden = false;
                    feedback.textContent = "Correct. " + explanation;
                    score += 1;
                } else {
                    feedback.hidden = false;
                    feedback.textContent = "Not quite. Correct answer: " + answer + ". " + explanation;
                }
            }

            var lessonKey = this.getAttribute("data-lesson-key") || "";
            var courseId = this.getAttribute("data-course-id") || "";
            var payload = {
                lesson_key: lessonKey,
                score: score,
                total_questions: totalQuestions,
                passed: totalQuestions > 0 && score === totalQuestions,
                answers: answers
            };
            if (courseId && lessonKey) {
                fetch("/learn/" + courseId + "/quiz-attempt", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify(payload)
                }).catch(function () {});
            }
            var summary = this.querySelector(".quiz-summary");
            if (summary) {
                summary.hidden = false;
                if (totalQuestions > 0 && score === totalQuestions) {
                    summary.textContent = "Score: " + score + "/" + totalQuestions + " - Passed.";
                } else {
                    summary.textContent = "Score: " + score + "/" + totalQuestions + " - Not passed yet.";
                }
            }
        });
    }
})();
