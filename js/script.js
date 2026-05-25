const loadBtn = document.getElementById("loadBtn");
        });

        classesCount.textContent = classes.size;
        individualsCount.textContent = individuals.size;

        showIndividuals(store);

    } catch (error) {

        console.error(error);

        resultsDiv.innerHTML = `
            <div class="individual-card">
                <h3>Error</h3>
                <p>No se pudo cargar la ontología.</p>
                <p>${error}</p>
            </div>
        `;
    }
}

function showIndividuals(store) {

    resultsDiv.innerHTML = "";

    const rdfType = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";

    const shown = new Set();

    store.statements.forEach(statement => {

        if (statement.predicate.value === rdfType) {

            const subject = statement.subject.value;
            const object = statement.object.value;

            const individualName = extractName(subject);
            const className = extractName(object);

            if (!shown.has(subject)) {

                shown.add(subject);

                const card = document.createElement("div");
                card.classList.add("individual-card");

                card.innerHTML = `
                    <h3>${individualName}</h3>
                    <p><strong>Clase:</strong> ${className}</p>
                `;

                resultsDiv.appendChild(card);
            }
        }
    });
}

function extractName(uri) {

    if (uri.includes("#")) {
        return uri.split("#").pop();
    }

    return uri.split("/").pop();
}