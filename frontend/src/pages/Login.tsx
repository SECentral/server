import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useQueryClient } from "@tanstack/react-query";
import {
  Alert,
  Button,
  Form,
  FormGroup,
  Page,
  PageSection,
  TextInput,
  Title
} from "@patternfly/react-core";
import { ApiError } from "../api/client";
import { createSession } from "../api/sessions";

export function Login() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    setSubmitting(true);
    setError(null);
    try {
      await createSession(username, password);
      await queryClient.invalidateQueries({ queryKey: ["session"] });
      navigate("/");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Unable to sign in.");
      setSubmitting(false);
    }
  };

  return (
    <Page>
      <PageSection className="pf-v6-u-mt-xl" isCenterAligned>
        <div className="pf-v6-u-mw-lg pf-v6-u-p-xl pf-v6-c-card">
          <Title headingLevel="h1">Log in to SECentral</Title>
          {error !== null && (
            <Alert variant="danger" isInline title={error} className="pf-v6-u-mb-md" />
          )}
          <Form onSubmit={(event) => void handleSubmit(event)}>
            <FormGroup label="Username" isRequired fieldId="login-username">
              <TextInput
                id="login-username"
                isRequired
                type="text"
                autoComplete="username"
                value={username}
                onChange={(_, value) => setUsername(value)}
              />
            </FormGroup>
            <FormGroup label="Password" isRequired fieldId="login-password">
              <TextInput
                id="login-password"
                isRequired
                type="password"
                autoComplete="current-password"
                value={password}
                onChange={(_, value) => setPassword(value)}
              />
            </FormGroup>
            <Button type="submit" variant="primary" isBlock isLoading={submitting}>
              Sign in
            </Button>
          </Form>
        </div>
      </PageSection>
    </Page>
  );
}
